// Copyright (C) 2019 ~ 2020 Uniontech Software Technology Co.,Ltd
// SPDX-FileCopyrightText: 2022 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "process_set.h"
#include "process/process_db.h"
#include "common/common.h"
#include "wm/wm_window_list.h"
// #include "settings.h"

#include <QDebug>
#include <QSet>

#include <algorithm>
#include <errno.h>

#define PROC_PATH "/proc"

using namespace common::error;

namespace core {
namespace process {

ProcessSet::ProcessSet()
    : m_set {}
    , m_recentProcStage {}
    , m_pidCtoPMapping {}
    , m_pidPtoCMapping {}
{
}

ProcessSet::ProcessSet(const ProcessSet &other)
    : m_set(other.m_set)
    , m_applicationResources(other.m_applicationResources)
    , m_recentProcStage(other.m_recentProcStage)
    , m_pidCtoPMapping(other.m_pidCtoPMapping)
    , m_pidPtoCMapping(other.m_pidPtoCMapping)
{
    m_prePid.clear();
    m_curPid.clear();
    m_pidMyApps.clear();
    m_simpleSet.clear();
    // m_settings = Settings::instance();
}

void ProcessSet::mergeSubProcNetIO(pid_t ppid, qreal &recvBps, qreal &sendBps,
                                   const QSet<pid_t> &excludedPids)
{
    if (excludedPids.contains(ppid) || !m_set.contains(ppid))
        return;

    auto it = m_pidPtoCMapping.find(ppid);
    while (it != m_pidPtoCMapping.end() && it.key() == ppid) {
        mergeSubProcNetIO(it.value(), recvBps, sendBps, excludedPids);
        ++it;
    }

    const Process &proc = m_set[ppid];
    recvBps += proc.recvBps();
    sendBps += proc.sentBps();
}

void ProcessSet::mergeSubProcCpu(pid_t ppid, qreal &cpu,
                                 const QSet<pid_t> &excludedPids)
{
    if (excludedPids.contains(ppid) || !m_set.contains(ppid))
        return;

    auto it = m_pidPtoCMapping.find(ppid);
    while (it != m_pidPtoCMapping.end() && it.key() == ppid) {
        mergeSubProcCpu(it.value(), cpu, excludedPids);
        ++it;
    }

    const Process &proc = m_set[ppid];
    cpu += proc.cpu();
}

void ProcessSet::mergeSubProcMemory(pid_t ppid, qulonglong &memory,
                                    const QSet<pid_t> &excludedPids)
{
    if (excludedPids.contains(ppid) || !m_set.contains(ppid))
        return;

    auto it = m_pidPtoCMapping.find(ppid);
    while (it != m_pidPtoCMapping.end() && it.key() == ppid) {
        mergeSubProcMemory(it.value(), memory, excludedPids);
        ++it;
    }

    memory += m_set[ppid].memory();
}

QMap<pid_t, QList<pid_t>> ProcessSet::collapseDesktopLaunchGroups(WMWindowList *windowList,
                                                                  uid_t euid,
                                                                  const QSet<pid_t> &reserved)
{
    using LaunchIdentity = QPair<QString, qlonglong>;

    auto launchIdentity = [](const Process &proc, LaunchIdentity &identity) -> bool {
        const QHash<QString, QString> environ = proc.environ();
        const QString desktopFile = environ.value("GIO_LAUNCHED_DESKTOP_FILE").trimmed();
        bool ok = false;
        const qlonglong launchPid =
                environ.value("GIO_LAUNCHED_DESKTOP_FILE_PID").toLongLong(&ok);
        if (desktopFile.isEmpty() || !ok || launchPid <= 0)
            return false;

        identity = qMakePair(desktopFile, launchPid);
        return true;
    };

    QMap<LaunchIdentity, QList<pid_t>> membersByLaunch;
    for (auto it = m_set.cbegin(); it != m_set.cend(); ++it) {
        if (it.value().uid() != euid || reserved.contains(it.key()))
            continue;

        LaunchIdentity identity;
        if (launchIdentity(it.value(), identity)) {
            // The desktop file and launcher PID identify one GIO launch while
            // keeping separate launches of the same application independent.
            membersByLaunch[identity].append(it.key());
        }
    }

    QMap<pid_t, QList<pid_t>> groups;
    for (auto groupIt = membersByLaunch.cbegin(); groupIt != membersByLaunch.cend(); ++groupIt) {
        QSet<pid_t> memberPids;
        QList<pid_t> pending = groupIt.value();
        while (!pending.isEmpty()) {
            const pid_t pid = pending.takeLast();
            if (memberPids.contains(pid) || !m_set.contains(pid) || reserved.contains(pid))
                continue;

            const Process &proc = m_set[pid];
            if (proc.uid() != euid)
                continue;

            LaunchIdentity identity;
            if (launchIdentity(proc, identity) && identity != groupIt.key())
                continue;

            memberPids.insert(pid);

            auto childIt = m_pidPtoCMapping.find(pid);
            while (childIt != m_pidPtoCMapping.end() && childIt.key() == pid) {
                pending.append(childIt.value());
                ++childIt;
            }
        }

        QList<pid_t> members = memberPids.values();
        std::sort(members.begin(), members.end());

        int rootCount = 0;
        QList<pid_t> appCandidates;
        for (pid_t pid : members) {
            if (!memberPids.contains(m_set[pid].ppid()))
                ++rootCount;
            if (m_set[pid].appType() == kFilterApps)
                appCandidates.append(pid);
        }

        // Group re-parented trees, and also collapse duplicate application rows
        // found inside one launch tree. A single application row in one tree is
        // handled by the normal recursive aggregation path.
        if (appCandidates.isEmpty() || (rootCount < 2 && appCandidates.size() < 2))
            continue;

        pid_t representativePid = -1;
        int representativeScore = -1;

        for (pid_t pid : appCandidates) {
            int score = 0;
            if (windowList->isGuiApp(pid))
                score = 3;
            else if (windowList->isDesktopEntryApp(pid))
                score = 2;
            else if (windowList->isTrayApp(pid))
                score = 1;

            if (score > representativeScore
                    || (score == representativeScore
                        && (representativePid < 0 || pid < representativePid))) {
                representativePid = pid;
                representativeScore = score;
            }
        }

        if (representativePid < 0)
            continue;

        m_set[representativePid].setAppType(kFilterApps);
        groups.insert(representativePid, members);
        for (pid_t pid : appCandidates) {
            if (pid == representativePid || m_set[pid].appType() != kFilterApps)
                continue;

            Process demoted = m_set[pid];
            demoted.detach();
            demoted.setAppType(kFilterCurrentUser);
            m_set.insert(pid, demoted);
            windowList->removeDesktopEntryApp(pid);
        }
    }

    return groups;
}

QMap<pid_t, QList<pid_t>> ProcessSet::collapseWineContainerGroups(WMWindowList *windowList,
                                                                  uid_t euid)
{
    using WineIdentity = QPair<QString, QString>;

    auto wineIdentity = [](const Process &proc, WineIdentity &identity) -> bool {
        const QHash<QString, QString> environ = proc.environ();
        const QString prefix = environ.value("WINEPREFIX").trimmed();
        const QString package = environ.value("DEB_PACKAGE_NAME").trimmed();
        if (prefix.isEmpty() || package.isEmpty())
            return false;

        identity = qMakePair(prefix, package);
        return true;
    };
    // Native processes spawned from inside the container (file manager,
    // browser, ...) inherit both variables too but are not Windows programs,
    // so they must not be folded into the wine application. Only the process
    // executable itself (argv[0]) is checked; a native process merely opening
    // a file named "setup.exe" must not match. Wine host processes (wineserver
    // and the deepin-wine loader shell) carry the same environment but no .exe
    // command line, so they are still treated as container members.
    const auto isWineContainerProcess = [](const Process &proc) {
        const QString name = proc.name();
        if (name == QStringLiteral("wineserver"))
            return true;
        if (name.startsWith(QStringLiteral("deepin-wine")))
            return true;
        if (name.endsWith(".exe", Qt::CaseInsensitive))
            return true;
        const QByteArrayList cmdline = proc.cmdline();
        return !cmdline.isEmpty()
                && QString::fromLocal8Bit(cmdline.value(0))
                           .contains(".exe", Qt::CaseInsensitive);
    };

    // A deepin-wine container (WINEPREFIX) hosts one logical application
    // (DEB_PACKAGE_NAME). Members that were re-parented to PID 1 still
    // inherit both variables, so this identity folds the whole container
    // into a single application row even across separate launches.
    QMap<WineIdentity, QList<pid_t>> membersByContainer;
    for (auto it = m_set.cbegin(); it != m_set.cend(); ++it) {
        if (it.value().uid() != euid)
            continue;

        const Process &proc = it.value();
        WineIdentity identity;
        if (wineIdentity(proc, identity) && isWineContainerProcess(proc))
            membersByContainer[identity].append(it.key());
    }

    QMap<pid_t, QList<pid_t>> groups;
    for (auto containerIt = membersByContainer.cbegin();
         containerIt != membersByContainer.cend(); ++containerIt) {
        QList<pid_t> members = containerIt.value();
        std::sort(members.begin(), members.end());

        QSet<pid_t> memberPids;
        for (pid_t pid : members)
            memberPids.insert(pid);

        int rootCount = 0;
        QList<pid_t> appCandidates;
        for (pid_t pid : members) {
            if (!memberPids.contains(m_set[pid].ppid()))
                ++rootCount;
            if (m_set[pid].appType() == kFilterApps)
                appCandidates.append(pid);
        }

        // A single application candidate living in one tree is handled by the
        // normal recursive aggregation path. Only re-parented or multi-launch
        // members need an explicit group so no resources are lost.
        if (appCandidates.isEmpty() || (rootCount < 2 && appCandidates.size() < 2))
            continue;

        pid_t representativePid = -1;
        int representativeScore = -1;
        for (pid_t pid : appCandidates) {
            int score = 0;
            if (windowList->isGuiApp(pid))
                score = 3;
            else if (windowList->isDesktopEntryApp(pid))
                score = 2;
            else if (windowList->isTrayApp(pid))
                score = 1;

            if (score > representativeScore
                    || (score == representativeScore
                        && (representativePid < 0 || pid < representativePid))) {
                representativePid = pid;
                representativeScore = score;
            }
        }

        if (representativePid < 0)
            continue;

        // m_set and m_simpleSet share the same ProcessPrivate (implicit sharing
        // without copy-on-write), so a demotion written directly would also
        // downgrade the birth-time cache and the member could never become a
        // representative again after the previous one exits. Detach the copy
        // before demoting so the persistent cache keeps its birth-time
        // classification and every scan re-derives the candidates.
        groups.insert(representativePid, members);
        for (pid_t pid : appCandidates) {
            if (pid == representativePid || m_set[pid].appType() != kFilterApps)
                continue;

            Process demoted = m_set[pid];
            demoted.detach();
            demoted.setAppType(kFilterCurrentUser);
            m_set.insert(pid, demoted);
            windowList->removeDesktopEntryApp(pid);
        }
    }

    return groups;
}

void ProcessSet::aggregateProcessGroup(pid_t representativePid, const QList<pid_t> &memberPids)
{
    if (!m_set.contains(representativePid))
        return;

    ApplicationResource resource;
    QSet<pid_t> visited;

    for (pid_t pid : memberPids) {
        if (visited.contains(pid) || !m_set.contains(pid))
            continue;
        visited.insert(pid);

        const Process &proc = m_set[pid];
        resource.cpu += proc.cpu();
        resource.recvBps += proc.recvBps();
        resource.sentBps += proc.sentBps();
        resource.memory += proc.memory();
    }

    m_applicationResources.insert(representativePid, resource);
}

void ProcessSet::refresh()
{
    scanProcess();
}

void ProcessSet::scanProcess()
{
    for (auto iter = m_set.begin(); iter != m_set.end(); iter++) {
        std::shared_ptr<RecentProcStage> procstage = std::make_shared<RecentProcStage>();
        procstage->ptime = iter->utime() + iter->stime();
        procstage->read_bytes = iter->readBytes();
        procstage->write_bytes = iter->writeBytes();
        procstage->cancelled_write_bytes = iter->cancelledWriteBytes();
        procstage->recv_bytes = iter->recvBytes();
        procstage->sent_bytes = iter->sentBytes();
        procstage->uptime = iter->procuptime();
        m_recentProcStage[iter->pid()] = procstage;
    }
    m_curPid.clear();
    m_set.clear();
    m_applicationResources.clear();
    m_pidPtoCMapping.clear();
    m_pidCtoPMapping.clear();
    WMWindowList *wmwindowList = ProcessDB::instance()->windowList();

    Iterator iter;
    while (iter.hasNext()) {
        Process proc = iter.next();

        if(!m_curPid.contains(proc.pid()))
            m_curPid.append(proc.pid());

    }

    if(m_prePid != m_curPid) {
        for (const pid_t &pid : m_prePid) {
            if(!m_curPid.contains(pid)){
                if(m_simpleSet.contains(pid))
                    m_simpleSet.remove(pid);
                m_pidMyApps.removeOne(pid);
            }
        }

        for (const pid_t &pid : m_curPid) {
            if(!m_prePid.contains(pid)){ //add  new process pid
                Process proc(pid);
                proc.readProcessSimpleInfo();
                if(!m_simpleSet.contains(pid))
                     m_simpleSet.insert(proc.pid(), proc);

                if (proc.appType() == kFilterApps && !wmwindowList->isTrayApp(proc.pid()))
                    m_pidMyApps.append(proc.pid());
            }
        }
        m_prePid = m_curPid;
    }

    // const QVariant &vindex = m_settings->getOption(kSettingKeyProcessTabIndex, kFilterApps);
    // int index = vindex.toInt();

    for (const pid_t &pid : m_prePid) {
        Process proc = m_simpleSet[pid];
        // if( ((kFilterApps == index) && (proc.appType()<= kFilterApps)) ||
        //     ((kFilterCurrentUser == index) && (proc.appType() <= kFilterCurrentUser)) ||
        //         (kNoFilter == index))
                {
             proc.readProcessVariableInfo();  //
               if (!proc.isValid())
                     continue;

               m_set.insert(proc.pid(), proc);
               m_pidPtoCMapping.insert(proc.ppid(), proc.pid());
               m_pidCtoPMapping.insert(proc.pid(), proc.ppid());
        }
    }

    const QMap<pid_t, QList<pid_t>> wineGroups =
            collapseWineContainerGroups(wmwindowList, ProcessDB::instance()->processEuid());
    QSet<pid_t> winePids;
    for (auto it = wineGroups.cbegin(); it != wineGroups.cend(); ++it) {
        winePids.insert(it.key());
        for (pid_t pid : it.value())
            winePids.insert(pid);
    }

    const QMap<pid_t, QList<pid_t>> launchGroups =
            collapseDesktopLaunchGroups(wmwindowList, ProcessDB::instance()->processEuid(),
                                        winePids);

    QMap<pid_t, QList<pid_t>> appGroups = wineGroups;
    for (auto it = launchGroups.cbegin(); it != launchGroups.cend(); ++it)
        appGroups.insert(it.key(), it.value());

    // A grouped subtree has its own application resource entry. Do not let
    // an ungrouped ancestor include it again through recursive aggregation.
    QSet<pid_t> groupedPids;
    for (auto it = appGroups.cbegin(); it != appGroups.cend(); ++it) {
        groupedPids.insert(it.key());
        for (pid_t pid : it.value())
            groupedPids.insert(pid);
    }

    // A split launch can choose a tray process or a previously hidden member
    // as its representative, neither of which is guaranteed to be in this list.
    for (auto it = appGroups.cbegin(); it != appGroups.cend(); ++it) {
        if (!m_pidMyApps.contains(it.key()))
            m_pidMyApps.append(it.key());
    }

    // find if any ancestor processes is gui application
    auto anyRootIsGuiProc = [&](pid_t ppid) -> bool {
        QSet<pid_t> visited;
        while (!visited.contains(ppid)) {
            visited.insert(ppid);
            if (wmwindowList->isGuiApp(ppid))
                return true;
            if (!m_pidCtoPMapping.contains(ppid))
                break;
            ppid = m_pidCtoPMapping.value(ppid);
        }
        return false;
    };

    for (const pid_t &pid : m_pidMyApps) {
        if (!m_set.contains(pid) || m_set[pid].appType() != kFilterApps)
            continue;

        if (appGroups.contains(pid)) {
            aggregateProcessGroup(pid, appGroups.value(pid));
        } else {
            ApplicationResource resource;
            mergeSubProcNetIO(pid, resource.recvBps, resource.sentBps, groupedPids);
            mergeSubProcCpu(pid, resource.cpu, groupedPids);
            mergeSubProcMemory(pid, resource.memory, groupedPids);
            m_applicationResources.insert(pid, resource);
        }

        // A split launch is already represented by this single selected PID.
        if (appGroups.contains(pid))
            continue;

        if (!wmwindowList->isGuiApp(pid))
        {
            // only if no ancestor process is gui app we keep this process
            if (m_pidCtoPMapping.contains(pid) &&
                    anyRootIsGuiProc(m_pidCtoPMapping[pid])) {

                // when we start app with deepin-terminal, we should skip setting apptype as CurrentUser
                const Process parentProc = getProcessById(m_pidCtoPMapping[pid]);
                QString parentCmdLineString = parentProc.cmdlineString();
                if (parentCmdLineString == QString("/bin/bash")) {
                    continue;
                }

                m_set[pid].setAppType(kFilterCurrentUser);
                wmwindowList->removeDesktopEntryApp(pid);
            }
        }
    }

    m_recentProcStage.clear();
}

ProcessSet::Iterator::Iterator()
{
    errno = 0;
    auto *dp = opendir(PROC_PATH);
    if (!dp) {
        print_errno(errno, "open /proc failed");
        return;
    }
    m_dir.reset(dp);

    advance();
}

bool ProcessSet::Iterator::hasNext()
{
    return m_dirent && isdigit(m_dirent->d_name[0]);
}

Process ProcessSet::Iterator::next()
{
    if (m_dirent && isdigit(m_dirent->d_name[0])) {
        auto pid = pid_t(atoi(m_dirent->d_name));
        Process proc(pid);

        advance();

            return proc;
    }

    return Process();
}

void ProcessSet::Iterator::advance()
{
    while ((m_dirent = readdir(m_dir.get()))) {
        if (isdigit(m_dirent->d_name[0]))
        if(pid_t(atoi(m_dirent->d_name)) < 10)
                continue;
        else 
            break;
    }
    if (!m_dirent && errno) {
        print_errno(errno, "read /proc failed");
    }
}

std::weak_ptr<RecentProcStage> ProcessSet::getRecentProcStage(pid_t pid) const
{
    return m_recentProcStage[pid];
}

QMap<pid_t, ApplicationResource> ProcessSet::getApplicationResources() const
{
    return m_applicationResources;
}

const Process ProcessSet::getProcessById(pid_t pid) const
{
    return m_set[pid];
}

QList<pid_t> ProcessSet::getPIDList() const
{
    // 当系统读取到的m_set为空时,通过keys()函数返回会造成段错误 原因是keys函数效率低下,会造成大量的内存拷贝
    // 替换方案是
    QList<pid_t> pidList {};
    pidList.clear();
    int size = m_set.size();
    QMap<pid_t, Process>::key_iterator iterBegin = m_set.keyBegin();
    for (;iterBegin != m_set.keyEnd(); ++iterBegin) {
        pid_t tmpKey = *iterBegin;
        pidList.append(tmpKey);
        if (size != m_set.size())
            break;
    }
    return pidList;
}

void ProcessSet::removeProcess(pid_t pid)
{
    m_set.remove(pid);
    m_applicationResources.remove(pid);
}

void ProcessSet::updateProcessState(pid_t pid, char state)
{
    if (m_set.contains(pid))
        m_set[pid].setState(state);
}

void ProcessSet::updateProcessPriority(pid_t pid, int priority)
{
    if (m_set.contains(pid))
        m_set[pid].setPriority(priority);
}

} // namespace process
} // namespace core
