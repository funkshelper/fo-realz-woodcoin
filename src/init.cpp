// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
#include "headers.h"
#include "db.h"
#include "bitcoinrpc.h"
#include "net.h"
#include "init.h"
#include "strlcpy.h"
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/interprocess/sync/file_lock.hpp>


using namespace std;
using namespace boost;

CWallet* pwalletMain;

//////////////////////////////////////////////////////////////////////////////
//
// Shutdown
//

void ExitTimeout(void* parg)
{
}

void Shutdown(void* parg)
{
    static CCriticalSection cs_Shutdown;
    static bool fTaken;
    bool fFirstThread = false;
    TRY_CRITICAL_BLOCK(cs_Shutdown)
    {
        fFirstThread = !fTaken;
        fTaken = true;
    }
    static bool fExit;
    if (fFirstThread)
    {
        fShutdown = true;
        nTransactionsUpdated++;
        DBFlush(false);
        StopNode();
        DBFlush(true);
        boost::filesystem::remove(GetPidFile());
        UnregisterWallet(pwalletMain);
        delete pwalletMain;
        CreateThread(ExitTimeout, NULL);
        Sleep(50);
        printf("Woodcoin exiting\n\n");
        fExit = true;
        exit(0);
    }
    else
    {
        while (!fExit)
            Sleep(500);
        Sleep(100);
        ExitThread(0);
    }
}

void HandleSIGTERM(int)
{
    fRequestShutdown = true;
}






//////////////////////////////////////////////////////////////////////////////
//
// Start
//

int main(int argc, char* argv[])
{
    bool fRet = false;
    fRet = AppInit(argc, argv);

    if (fRet && fDaemon)
        return 0;

    return 1;
}


bool AppInit(int argc, char* argv[])
{
    bool fRet = false;
    try
    {
        fRet = AppInit2(argc, argv);
    }
    catch (std::exception& e) {
        PrintException(&e, "AppInit()");
    } catch (...) {
        PrintException(NULL, "AppInit()");
    }
    if (!fRet)
        Shutdown(NULL);
    return fRet;
}

bool AppInit2(int argc, char* argv[])
{
    umask(077);

    // Clean shutdown on SIGTERM
    struct sigaction sa;
    sa.sa_handler = HandleSIGTERM;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    //
    // Parameters
    //
    ParseParameters(argc, argv);

    if (mapArgs.count("-datadir"))
    {
        if (filesystem::is_directory(filesystem::system_complete(mapArgs["-datadir"])))
        {
            filesystem::path pathDataDir = filesystem::system_complete(mapArgs["-datadir"]);
            strlcpy(pszSetDataDir, pathDataDir.string().c_str(), sizeof(pszSetDataDir));
        }
        else
        {
            fprintf(stderr, "Error: Specified directory does not exist\n");
            Shutdown(NULL);
        }
    }


    ReadConfigFile(mapArgs, mapMultiArgs); // Must be done after processing datadir

    if (mapArgs.count("-?") || mapArgs.count("--help"))
    {
        string strUsage = string() +
          _("Woodcoin version") + " " + FormatFullVersion() + "\n\n" +
          _("Usage:") + "\t\t\t\t\t\t\t\t\t\t\n" +
            "  woodcoind [options]                   \t  " + "\n" +
            "  woodcoind [options] <command> [params]\t  " + _("Send command to -server or woodcoind\n") +
            "  woodcoind [options] help              \t\t  " + _("List commands\n") +
            "  woodcoind [options] help <command>    \t\t  " + _("Get help for a command\n") +
          _("Options:\n") +
            "  -conf=<file>     \t\t  " + _("Specify configuration file (default: woodcoin.conf)\n") +
            "  -pid=<file>      \t\t  " + _("Specify pid file (default: woodcoind.pid)\n") +
            "  -gen             \t\t  " + _("Generate coins\n") +
            "  -gen=0           \t\t  " + _("Don't generate coins\n") +
            "  -min             \t\t  " + _("Start minimized\n") +
            "  -datadir=<dir>   \t\t  " + _("Specify data directory\n") +
            "  -timeout=<n>     \t  "   + _("Specify connection timeout (in milliseconds)\n") +
            "  -proxy=<ip:port> \t  "   + _("Connect through socks4 proxy\n") +
            "  -port=<port>     \t\t  " + _("Listen for connections on <port> (default: 8338)\n") +
            "  -maxconnections=<n>\t  " + _("Maintain at most <n> connections to peers (default: 125)\n") +
            "  -myip=<ip>       \t  "   + _("Set this node's external IP address.\n") +
            "  -addnode=<ip>    \t  "   + _("Add a node to connect to\n") +
            "  -connect=<ip>    \t\t  " + _("Connect only to the specified node\n") +
            "  -nolisten        \t  "   + _("Don't accept connections from outside\n") +
            "  -banscore=<n>    \t  "   + _("Threshold for disconnecting misbehaving peers (default: 100)\n") +
            "  -bantime=<n>     \t  "   + _("Number of seconds to keep misbehaving peers from reconnecting (default: 86400)\n") +
            "  -maxreceivebuffer=<n>\t  " + _("Maximum per-connection receive buffer, <n>*1000 bytes (default: 10000)\n") +
            "  -maxsendbuffer=<n>\t  "   + _("Maximum per-connection send buffer, <n>*1000 bytes (default: 10000)\n") +
            "  -paytxfee=<amt>  \t  "   + _("Fee per kB to add to transactions you send\n") +
            "  -daemon          \t\t  " + _("Run in the background as a daemon and accept commands\n") +
            "  -debug           \t\t  " + _("Output extra debugging information\n") +
	        "  -caneat          \t\t  " + _("Permit the use of 'eatblock'\n") +
            "  -logtimestamps   \t  "   + _("Prepend debug output with timestamp\n") +
            "  -printtoconsole  \t  "   + _("Send trace/debug info to console instead of debug.log file\n") +
            "  -rpcuser=<user>  \t  "   + _("Username for JSON-RPC connections\n") +
            "  -rpcpassword=<pw>\t  "   + _("Password for JSON-RPC connections\n") +
            "  -rpcport=<port>  \t\t  " + _("Listen for JSON-RPC connections on <port> (default: 8332)\n") +
            "  -rpcallowip=<ip> \t\t  " + _("Allow JSON-RPC connections from specified IP address\n") +
            "  -rpcconnect=<ip> \t  "   + _("Send commands to node running on <ip> (default: 127.0.0.1)\n") +
            "  -keypool=<n>     \t  "   + _("Set key pool size to <n> (default: 100)\n") +
            "  -rescan          \t  "   + _("Rescan the block chain for missing wallet transactions\n");

        strUsage += string() +
            "  -?               \t\t  " + _("This help message\n");

        // Remove tabs
        strUsage.erase(std::remove(strUsage.begin(), strUsage.end(), '\t'), strUsage.end());
        fprintf(stderr, "%s", strUsage.c_str());
        return false;
    }

    fDebug = GetBoolArg("-debug");
    fDaemon = GetBoolArg("-daemon");
    fCanEat = GetBoolArg("-caneat");

    if (fDaemon)
        fServer = true;
    else
        fServer = GetBoolArg("-server");

    /* force fServer when running without GUI */
    fServer = true;
    fPrintToConsole = GetBoolArg("-printtoconsole");
    fPrintToDebugger = GetBoolArg("-printtodebugger");
    fLogTimestamps = GetBoolArg("-logtimestamps");

    for (int i = 1; i < argc; i++)
        if (!IsSwitchChar(argv[i][0]))
            fCommandLine = true;

    if (fCommandLine)
    {
        int ret = CommandLineRPC(argc, argv);
        exit(ret);
    }

    if (fDaemon)
    {
        // Daemonize
        pid_t pid = fork();
        if (pid < 0)
        {
            fprintf(stderr, "Error: fork() returned %d errno %d\n", pid, errno);
            return false;
        }
        if (pid > 0)
        {
            CreatePidFile(GetPidFile(), pid);
            return true;
        }

        pid_t sid = setsid();
        if (sid < 0)
            fprintf(stderr, "Error: setsid() returned %d errno %d\n", sid, errno);
    }

    if (!fDebug && !pszSetDataDir[0])
        ShrinkDebugFile();
    printf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    printf("Woodcoin version %s\n", FormatFullVersion().c_str());
    printf("Default data directory %s\n", GetDefaultDataDir().c_str());

    if (GetBoolArg("-loadblockindextest"))
    {
        CTxDB txdb("r");
        txdb.LoadBlockIndex();
        PrintBlockTree();
        return false;
    }

    // Make sure only a single bitcoin process is using the data directory.
    string strLockFile = GetDataDir() + "/.lock";
    FILE* file = fopen(strLockFile.c_str(), "a"); // empty lock file; created if it doesn't exist.
    if (file) fclose(file);
    static boost::interprocess::file_lock lock(strLockFile.c_str());
    if (!lock.try_lock())
    {
        wxMessageBox(strprintf(_("Cannot obtain a lock on data directory %s.  Woodcoin is probably already running."), GetDataDir().c_str()), "Woodcoin");
        return false;
    }

    string strErrors;

    //
    // Load data files
    //
    if (fDaemon)
        fprintf(stdout, "woodcoin server starting\n");
    strErrors = "";
    int64 nStart;

    InitMessage(_("Loading addresses..."));
    printf("Loading addresses...\n");
    nStart = GetTimeMillis();
    if (!LoadAddresses())
        strErrors += _("Error loading addr.dat      \n");
    printf(" addresses   %15"PRI64d"ms\n", GetTimeMillis() - nStart);

    InitMessage(_("Loading block index..."));
    printf("Loading block index...\n");
    nStart = GetTimeMillis();
    if (!LoadBlockIndex()) {
        strErrors += _("Error loading blkindex.dat      \n");
        printf("LoadBlockINdex returned false");
    }
    printf(" block index %15"PRI64d"ms\n", GetTimeMillis() - nStart);

    InitMessage(_("Loading wallet..."));
    printf("Loading wallet...\n");
    nStart = GetTimeMillis();
    bool fFirstRun;
    pwalletMain = new CWallet("wallet.dat");
    int nLoadWalletRet = pwalletMain->LoadWallet(fFirstRun);
    if (nLoadWalletRet != DB_LOAD_OK)
    {
        if (nLoadWalletRet == DB_CORRUPT)
            strErrors += _("Error loading wallet.dat: Wallet corrupted      \n");
        else if (nLoadWalletRet == DB_TOO_NEW)
            strErrors += _("Error loading wallet.dat: Wallet requires newer version of Woodcoin      \n");
        else if (nLoadWalletRet == DB_NEED_REWRITE)
        {
            strErrors += _("Wallet needed to be rewritten: restart Woodcoin to complete    \n");
            wxMessageBox(strErrors, "Woodcoin", wxOK | wxICON_ERROR);
            return false;
        }
        else
            strErrors += _("Error loading wallet.dat      \n");
    }
    printf(" wallet      %15"PRI64d"ms\n", GetTimeMillis() - nStart);

    RegisterWallet(pwalletMain);

    CBlockIndex *pindexRescan = pindexBest;
    if (GetBoolArg("-rescan"))
        pindexRescan = pindexGenesisBlock;
    else
    {
        CWalletDB walletdb("wallet.dat");
        CBlockLocator locator;
        if (walletdb.ReadBestBlock(locator))
            pindexRescan = locator.GetBlockIndex();
    }
    if (pindexBest != pindexRescan)
    {
        InitMessage(_("Rescanning..."));
        printf("Rescanning last %i blocks (from block %i)...\n", pindexBest->nHeight - pindexRescan->nHeight, pindexRescan->nHeight);
        nStart = GetTimeMillis();
        pwalletMain->ScanForWalletTransactions(pindexRescan, true);
        printf(" rescan      %15"PRI64d"ms\n", GetTimeMillis() - nStart);
    }

    InitMessage(_("Done loading"));
    printf("Done loading\n");

        //// debug print
        printf("mapBlockIndex.size() = %d\n",   mapBlockIndex.size());
        printf("nBestHeight = %d\n",            nBestHeight);
        printf("setKeyPool.size() = %d\n",      pwalletMain->setKeyPool.size());
        printf("mapWallet.size() = %d\n",       pwalletMain->mapWallet.size());
        printf("mapAddressBook.size() = %d\n",  pwalletMain->mapAddressBook.size());

    if (!strErrors.empty())
    {
        wxMessageBox(strErrors, "Woodcoin", wxOK | wxICON_ERROR);
        return false;
    }

    // Add wallet transactions that aren't already in a block to mapTransactions
    pwalletMain->ReacceptWalletTransactions();

    // Note: Bitcoin-QT stores several settings in the wallet, so we want
    // to load the wallet BEFORE parsing command-line arguments, so
    // the command-line/bitcoin.conf settings override GUI setting.

    //
    // Parameters
    //
    if (GetBoolArg("-printblockindex") || GetBoolArg("-printblocktree"))
    {
        PrintBlockTree();
        return false;
    }

    if (mapArgs.count("-timeout"))
    {
        int nNewTimeout = GetArg("-timeout", 5000);
        if (nNewTimeout > 0 && nNewTimeout < 600000)
            nConnectTimeout = nNewTimeout;
    }

    if (mapArgs.count("-printblock"))
    {
        string strMatch = mapArgs["-printblock"];
        int nFound = 0;
        for (map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
        {
            uint256 hash = (*mi).first;
            if (strncmp(hash.ToString().c_str(), strMatch.c_str(), strMatch.size()) == 0)
            {
                CBlockIndex* pindex = (*mi).second;
                CBlock block;
                block.ReadFromDisk(pindex);
                block.BuildMerkleTree();
                block.print();
                printf("\n");
                nFound++;
            }
        }
        if (nFound == 0)
            printf("No blocks matching %s were found\n", strMatch.c_str());
        return false;
    }

    fGenerateBitcoins = GetBoolArg("-gen");

    if (mapArgs.count("-proxy"))
    {
        fUseProxy = true;
        addrProxy = CAddress(mapArgs["-proxy"]);
        if (!addrProxy.IsValid())
        {
            wxMessageBox(_("Invalid -proxy address"), "Woodcoin");
            return false;
        }
    }

    bool fTor = (fUseProxy && addrProxy.port == htons(9050));
    if (fTor)
    {
        // Use SoftSetArg here so user can override any of these if they wish.
        // Note: the GetBoolArg() calls for all of these must happen later.
        SoftSetArg("-nolisten", true);
    }

    fNoListen = GetBoolArg("-nolisten");

    // Command-line args override in-wallet settings:

    if (!fNoListen)
    {
        if (!BindListenPort(strErrors))
        {
            wxMessageBox(strErrors, "Woodcoin");
            return false;
        }
    }

    if (mapArgs.count("-addnode"))
    {
        BOOST_FOREACH(string strAddr, mapMultiArgs["-addnode"])
        {
            CAddress addr(strAddr);
            addr.nTime = 0; // so it won't relay unless successfully connected
            if (addr.IsValid())
                AddAddress(addr);
        }
    }

    if (mapArgs.count("-paytxfee"))
    {
        if (!ParseMoney(mapArgs["-paytxfee"], nTransactionFee))
        {
            wxMessageBox(_("Invalid amount for -paytxfee=<amount>"), "Woodcoin");
            return false;
        }
        if (nTransactionFee > 0.25 * COIN)
            wxMessageBox(_("Warning: -paytxfee is set very high.  This is the transaction fee you will pay if you send a transaction."), "Woodcoin", wxOK | wxICON_EXCLAMATION);
    }

    //
    // Start the node
    //
    if (!CheckDiskSpace())
        return false;

    RandAddSeedPerfmon();

    if (!CreateThread(StartNode, NULL))
        wxMessageBox(_("Error: CreateThread(StartNode) failed"), "Woodcoin");

    if (fServer)
        CreateThread(ThreadRPCServer, NULL);

    while (1)
        Sleep(5000);

    return true;
}
