//Modified by Nishka Dasgupta, Akash Shah

#include "Network/BtEndpoint.h"

#include "OPPRF/OPPRFReceiver.h"
#include "OPPRF/OPPRFSender.h"

#include "../MPCHonestMajority/MPSI_Party.h"

#include <fstream>
using namespace osuCrypto;
#include "util.h"

#include "Common/Defines.h"
#include "NChooseOne/KkrtNcoOtReceiver.h"
#include "NChooseOne/KkrtNcoOtSender.h"

#include "NChooseOne/Oos/OosNcoOtReceiver.h"
#include "NChooseOne/Oos/OosNcoOtSender.h"
#include "Common/Log.h"
#include "Common/Log1.h"
#include "Common/Timer.h"
#include "Crypto/PRNG.h"
#include <numeric>
#include <iostream>

#include "add_on.h"

void party3_original(u64 myIdx, u64 setSize, u64 nTrials)
{
    u64 opt = 0;
    u64 nParties(3);
	std::fstream runtime;
	if (myIdx == 0)
		runtime.open("./runtime3.txt", runtime.trunc | runtime.out);

	u64 offlineAvgTime(0), hashingAvgTime(0), getOPRFAvgTime(0),
		secretSharingAvgTime(0), intersectionAvgTime(0), onlineAvgTime(0);

	u64  psiSecParam = 40, bitSize = 128, numThreads = 1;
	PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

	std::string name("psi");
	BtIOService ios(0);

	int btCount = nParties;
	std::vector<BtEndpoint> ep(nParties);

	u64 offlineTimeTot(0);
	u64 onlineTimeTot(0);
	Timer timer;

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i < myIdx)
		{
			u32 port = 1120 + i * 100 + myIdx;//get the same port; i=1 & pIdx=2 =>port=102
			ep[i].start(ios, "localhost", port, false, name); //channel bwt i and pIdx, where i is sender
		}
		else if (i > myIdx)
		{
			u32 port = 1120 + myIdx * 100 + i;//get the same port; i=2 & pIdx=1 =>port=102
			ep[i].start(ios, "localhost", port, true, name); //channel bwt i and pIdx, where i is receiver
		}
	}


	std::vector<std::vector<Channel*>> chls(nParties);

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i != myIdx) {
			chls[i].resize(numThreads);
			for (u64 j = 0; j < numThreads; ++j)
			{
				//chls[i][j] = &ep[i].addChannel("chl" + std::to_string(j), "chl" + std::to_string(j));
				chls[i][j] = &ep[i].addChannel(name, name);
			}
		}
	}

	PRNG prngSame(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
	PRNG prngDiff(_mm_set_epi32(434653, 23, myIdx, myIdx));
	u64 expected_intersection;
	u64 num_intersection;
	double dataSent = 0, Mbps = 0, dateRecv = 0, MbpsRecv = 0;

	for (u64 idxTrial = 0; idxTrial < nTrials; idxTrial++)
	{
		std::vector<block> set(setSize);

		block blk_rand = prngSame.get<block>();
		expected_intersection = (*(u64*)&blk_rand) % setSize;

		for (u64 i = 0; i < expected_intersection; ++i)
		{
			set[i] = prngSame.get<block>();
		}

		for (u64 i = expected_intersection; i < setSize; ++i)
		{
			set[i] = prngDiff.get<block>();
		}

		std::vector<block> sendPayLoads(setSize);
		std::vector<block> recvPayLoads(setSize);

		//only P0 genaretes secret sharing
		if (myIdx == 0)
		{
			for (u64 i = 0; i < setSize; ++i)
				sendPayLoads[i] = prng.get<block>();
		}

		std::vector<KkrtNcoOtReceiver> otRecv(nParties);
		std::vector<KkrtNcoOtSender> otSend(nParties);

		OPPRFSender send;
		OPPRFReceiver recv;
		binSet bins;

		std::vector<std::thread>  pThrds(nParties);

		//##########################
		//### Offline Phasing
		//##########################

		auto start = timer.setTimePoint("start");

		bins.init(myIdx, nParties, setSize, psiSecParam, opt);
		u64 otCountSend = bins.mSimpleBins.mBins.size();
		u64 otCountRecv = bins.mCuckooBins.mBins.size();

		u64 nextNeibough = (myIdx + 1) % nParties;
		u64 prevNeibough = (myIdx - 1 + nParties) % nParties;

		for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
		{
			pThrds[pIdx] = std::thread([&, pIdx]() {
				if (pIdx == nextNeibough) {
					//I am a sender to my next neigbour
					send.init(opt, nParties, setSize, psiSecParam, bitSize, chls[pIdx], otCountSend, otSend[pIdx], otRecv[pIdx], prng.get<block>(), false);

				}
				else if (pIdx == prevNeibough) {
					//I am a recv to my previous neigbour
					recv.init(opt, nParties, setSize, psiSecParam, bitSize, chls[pIdx], otCountRecv, otRecv[pIdx], otSend[pIdx], ZeroBlock, false);
				}
			});
		}

		for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
			pThrds[pIdx].join();

#ifdef PRINT
		std::cout << IoStream::lock;
		if (myIdx == 0)
		{
			Log::out << "------0------" << Log::endl;
			Log::out << otSend[1].mGens[0].get<block>() << Log::endl;
			Log::out << otRecv[2].mGens[0][0].get<block>() << Log::endl;
			Log::out << otRecv[2].mGens[0][1].get<block>() << Log::endl;
		}
		if (myIdx == 1)
		{
			Log::out << "------1------" << Log::endl;
			Log::out << otRecv[0].mGens[0][0].get<block>() << Log::endl;
			Log::out << otRecv[0].mGens[0][1].get<block>() << Log::endl;
			Log::out << otSend[2].mGens[0].get<block>() << Log::endl;
		}

		if (myIdx == 2)
		{
			Log::out << "------2------" << Log::endl;
			Log::out << otRecv[1].mGens[0][0].get<block>() << Log::endl;
			Log::out << otRecv[1].mGens[0][1].get<block>() << Log::endl;
			Log::out << otSend[0].mGens[0].get<block>() << Log::endl;
		}
		std::cout << IoStream::unlock;
#endif

		auto initDone = timer.setTimePoint("initDone");

		//##########################
		//### Hashing
		//##########################
		bins.hashing2Bins(set, nParties);
		//bins.mSimpleBins.print(myIdx, true, false, false, false);
		//bins.mCuckooBins.print(myIdx, true, false, false);

		auto hashingDone = timer.setTimePoint("hashingDone");

		//##########################
		//### Online Phasing - compute OPRF
		//##########################

		pThrds.clear();
		pThrds.resize(nParties);
		for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
		{
			pThrds[pIdx] = std::thread([&, pIdx]() {

				if (pIdx == nextNeibough) {
					//I am a sender to my next neigbour
					send.getOPRFkeys(pIdx, bins, chls[pIdx], false);
				}
				else if (pIdx == prevNeibough) {
					//I am a recv to my previous neigbour
					recv.getOPRFkeys(pIdx, bins, chls[pIdx], false);

				}
			});
		}

		for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
			pThrds[pIdx].join();

		//if (myIdx == 2)
		//{
		//	//bins.mSimpleBins.print(2, true, true, false, false);
		//	bins.mCuckooBins.print(1, true, true, false);
		//	Log::out << "------------" << Log::endl;
		//}
		//if (myIdx == 1)
		//{
		//	bins.mSimpleBins.print(2, true, true, false, false);
		//	//bins.mCuckooBins.print(0, true, true, false);
		//}

		auto getOPRFDone = timer.setTimePoint("getOPRFDone");


		//##########################
		//### online phasing - secretsharing
		//##########################

		pThrds.clear();
		pThrds.resize(nParties - 1);

		if (myIdx == 0)
		{
			//for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
			//{
			//	pThrds[pIdx] = std::thread([&, pIdx]() {
			//		if (pIdx == 0) {
			//			send.sendSSTableBased(nextNeibough, bins, sendPayLoads, chls[nextNeibough]);
			//		}
			//		else if (pIdx == 1) {
			//			recv.recvSSTableBased(prevNeibough, bins, recvPayLoads, chls[prevNeibough]);
			//		}
			//	});
			//}
			send.sendSSTableBased(nextNeibough, bins, sendPayLoads, chls[nextNeibough]);
			recv.recvSSTableBased(prevNeibough, bins, recvPayLoads, chls[prevNeibough]);
		}
		else
		{
			/*for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
			{
			pThrds[pIdx] = std::thread([&, pIdx]() {
			if (pIdx == 0) {
			recv.recvSSTableBased(prevNeibough, bins, recvPayLoads, chls[prevNeibough]);
			}
			else if (pIdx == 1) {
			send.sendSSTableBased(nextNeibough, bins, recvPayLoads, chls[nextNeibough]);
			}
			});
			}	*/
			recv.recvSSTableBased(prevNeibough, bins, recvPayLoads, chls[prevNeibough]);
			//sendPayLoads = recvPayLoads;
			send.sendSSTableBased(nextNeibough, bins, recvPayLoads, chls[nextNeibough]);

		}

		/*for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
		pThrds[pIdx].join();*/

		auto getSSDone = timer.setTimePoint("getSSDone");

#ifdef PRINT
		std::cout << IoStream::lock;
		if (myIdx == 0)
		{
			for (int i = 0; i < 5; i++)
			{
				Log::out << sendPayLoads[i] << Log::endl;
				//Log::out << recvPayLoads[2][i] << Log::endl;
			}
			Log::out << "------------" << Log::endl;
		}
		if (myIdx == 1)
		{
			for (int i = 0; i < 5; i++)
			{
				//Log::out << recvPayLoads[i] << Log::endl;
				Log::out << sendPayLoads[i] << Log::endl;
			}
		}
		if (myIdx == 2)
		{
			for (int i = 0; i < 5; i++)
			{
				Log::out << sendPayLoads[i] << Log::endl;
			}
		}
		std::cout << IoStream::unlock;
#endif

		//##########################
		//### online phasing - compute intersection
		//##########################

		std::vector<u64> mIntersection;

		if (myIdx == 0) {


			for (u64 i = 0; i < setSize; ++i)
			{
				if (!memcmp((u8*)&sendPayLoads[i], &recvPayLoads[i], bins.mMaskSize))
				{
					mIntersection.push_back(i);
				}
			}
			Log::out << "mIntersection.size(): " << mIntersection.size() << Log::endl;
		}
		auto getIntersection = timer.setTimePoint("getIntersection");

		num_intersection = mIntersection.size();


		if (myIdx == 0) {
			auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(initDone - start).count();
			auto hashingTime = std::chrono::duration_cast<std::chrono::milliseconds>(hashingDone - initDone).count();
			auto getOPRFTime = std::chrono::duration_cast<std::chrono::milliseconds>(getOPRFDone - hashingDone).count();
			auto secretSharingTime = std::chrono::duration_cast<std::chrono::milliseconds>(getSSDone - getOPRFDone).count();
			auto intersectionTime = std::chrono::duration_cast<std::chrono::milliseconds>(getIntersection - getSSDone).count();

			double onlineTime = hashingTime + getOPRFTime + secretSharingTime + intersectionTime;

			double time = offlineTime + onlineTime;
			time /= 1000;


			dataSent = 0;
			dateRecv = 0;
			Mbps = 0;
			MbpsRecv = 0;

			for (u64 i = 0; i < nParties; ++i)
			{
				if (i != myIdx) {
					chls[i].resize(numThreads);
					for (u64 j = 0; j < numThreads; ++j)
					{
						dataSent += chls[i][j]->getTotalDataSent();
						dateRecv += chls[i][j]->getTotalDataRecv();
					}
				}
			}

			Mbps = dataSent * 8 / time / (1 << 20);
			MbpsRecv = dataSent * 8 / time / (1 << 20);

			for (u64 i = 0; i < nParties; ++i)
			{
				if (i != myIdx) {
					chls[i].resize(numThreads);
					for (u64 j = 0; j < numThreads; ++j)
					{
						chls[i][j]->resetStats();
					}
				}
			}


			Log::out << "#Output Intersection: " << num_intersection << Log::endl;
			Log::out << "#Expected Intersection: " << expected_intersection << Log::endl;

			std::cout << "(ROUND OPPRF) numParty: " << nParties
				<< "  setSize: " << setSize << "\n"
				<< "offlineTime:  " << offlineTime << " ms\n"
				<< "hashingTime:  " << hashingTime << " ms\n"
				<< "getOPRFTime:  " << getOPRFTime << " ms\n"
				<< "secretSharing:  " << secretSharingTime << " ms\n"
				<< "intersection:  " << intersectionTime << " ms\n"
				<< "onlineTime:  " << onlineTime << " ms\n"
				//<< "Bandwidth: Send: " << Mbps << " Mbps,\t Recv: " << MbpsRecv << " Mbps\n"
				<< "Total time: " << time << " s\n"
				//<< "Total Comm: Send:" << (dataSent / std::pow(2.0, 20)) << " MB"
				//<< "\t Recv: " << (dateRecv / std::pow(2.0, 20)) << " MB\n"
				<< "------------------\n";


			offlineAvgTime += offlineTime;
			hashingAvgTime += hashingTime;
			getOPRFAvgTime += getOPRFTime;
			secretSharingAvgTime += secretSharingTime;
			intersectionAvgTime += intersectionTime;
			onlineAvgTime += onlineTime;
		}
	}

	if (myIdx == 0) {
		double avgTime = (offlineAvgTime + onlineAvgTime);
		avgTime /= 1000;
		std::cout << "=========avg==========\n"
			<< "(ROUND OPPRF) numParty: " << nParties
			<< "  setSize: " << setSize
			<< "  nTrials:" << nTrials << "\n"
			<< "offlineTime:  " << offlineAvgTime / nTrials << " ms\n"
			<< "hashingTime:  " << hashingAvgTime / nTrials << " ms\n"
			<< "getOPRFTime:  " << getOPRFAvgTime / nTrials << " ms\n"
			<< "secretSharing:  " << secretSharingAvgTime / nTrials << " ms\n"
			<< "intersection:  " << intersectionAvgTime / nTrials << " ms\n"
			<< "onlineTime:  " << onlineAvgTime / nTrials << " ms\n"
			//<< "Bandwidth: Send: " << Mbps << " Mbps,\t Recv: " << MbpsRecv << " Mbps\n"
			<< "Total time: " << avgTime/ nTrials << " s\n"
			//<< "Total Comm: Send:" << (dataSent / std::pow(2.0, 20)) << " MB"
			//<< "\t Recv: " << (dateRecv / std::pow(2.0, 20)) << " MB\n"
			<< "------------------\n";

		runtime << "(ROUND OPPRF) numParty: " << nParties
			<< "  setSize: " << setSize
			<< "  nTrials:" << nTrials << "\n"
			<< "offlineTime:  " << offlineAvgTime / nTrials << " ms\n"
			<< "hashingTime:  " << hashingAvgTime / nTrials << " ms\n"
			<< "getOPRFTime:  " << getOPRFAvgTime / nTrials << " ms\n"
			<< "secretSharing:  " << secretSharingAvgTime / nTrials << " ms\n"
			<< "intersection:  " << intersectionAvgTime / nTrials << " ms\n"
			<< "onlineTime:  " << onlineAvgTime / nTrials << " ms\n"
			//<< "Bandwidth: Send: " << Mbps << " Mbps,\t Recv: " << MbpsRecv << " Mbps\n"
			<< "Total time: " << avgTime / nTrials << " s\n"
			//<< "Total Comm: Send:" << (dataSent / std::pow(2.0, 20)) << " MB"
			//<< "\t Recv: " << (dateRecv / std::pow(2.0, 20)) << " MB\n"
			<< "------------------\n";
		runtime.close();
	}

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i != myIdx)
		{
			for (u64 j = 0; j < numThreads; ++j)
			{
				chls[i][j]->close();
			}
		}
	}

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i != myIdx)
			ep[i].stop();
	}


	ios.stop();
}



void party3_edited(u64 myIdx, std::string inputfile, std::string outputfile)
{
    u64 opt = 0;
    u64 nParties(3);
	std::fstream runtime;
    u64 nTrials = 1;
	if (myIdx == 0)
		runtime.open("./runtime3.txt", runtime.trunc | runtime.out);

	u64 offlineAvgTime(0), hashingAvgTime(0), getOPRFAvgTime(0),
		secretSharingAvgTime(0), intersectionAvgTime(0), onlineAvgTime(0);

	u64  psiSecParam = 40, bitSize = 128, numThreads = 1;
	PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

	std::string name("psi");
	BtIOService ios(0);

	int btCount = nParties;
	std::vector<BtEndpoint> ep(nParties);

	u64 offlineTimeTot(0);
	u64 onlineTimeTot(0);
	Timer timer;

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i < myIdx)
		{
			u32 port = 1120 + i * 100 + myIdx;//get the same port; i=1 & pIdx=2 =>port=102
			ep[i].start(ios, "localhost", port, false, name); //channel bwt i and pIdx, where i is sender
		}
		else if (i > myIdx)
		{
			u32 port = 1120 + myIdx * 100 + i;//get the same port; i=2 & pIdx=1 =>port=102
			ep[i].start(ios, "localhost", port, true, name); //channel bwt i and pIdx, where i is receiver
		}
	}


	std::vector<std::vector<Channel*>> chls(nParties);

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i != myIdx) {
			chls[i].resize(numThreads);
			for (u64 j = 0; j < numThreads; ++j)
			{
				//chls[i][j] = &ep[i].addChannel("chl" + std::to_string(j), "chl" + std::to_string(j));
				chls[i][j] = &ep[i].addChannel(name, name);
			}
		}
	}

	PRNG prngSame(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
	PRNG prngDiff(_mm_set_epi32(434653, 23, myIdx, myIdx));
	u64 expected_intersection;
	u64 num_intersection;
	double dataSent = 0, Mbps = 0, dateRecv = 0, MbpsRecv = 0;

	for (u64 idxTrial = 0; idxTrial < nTrials; idxTrial++)
	{
        u64 setSize = 128;
		std::vector<block> set(setSize);

		// block blk_rand = prngSame.get<block>();
		// expected_intersection = (*(u64*)&blk_rand) % setSize;
        expected_intersection = 64;

		for (u64 i = 0; i < expected_intersection; ++i)
		{
			set[i] = prngSame.get<block>();
		}

		for (u64 i = expected_intersection; i < setSize; ++i)
		{
			set[i] = prngDiff.get<block>();
		}

        // vector<block> set;
        // read_input_file(inputfile, set);
        // u64 setSize = set.size();
        // if (setSize <= 0){
        //     std::cout << "read input file error, tast abort." << std::endl;
        //     return;
        // }

		std::vector<block> sendPayLoads(setSize);
		std::vector<block> recvPayLoads(setSize);

		//only P0 genaretes secret sharing
		if (myIdx == 0)
		{
			for (u64 i = 0; i < setSize; ++i)
				sendPayLoads[i] = prng.get<block>();
		}

		std::vector<KkrtNcoOtReceiver> otRecv(nParties);
		std::vector<KkrtNcoOtSender> otSend(nParties);

		OPPRFSender send;
		OPPRFReceiver recv;
		binSet bins;

		std::vector<std::thread>  pThrds(nParties);

		//##########################
		//### Offline Phasing
		//##########################

		auto start = timer.setTimePoint("start");

		bins.init(myIdx, nParties, setSize, psiSecParam, opt);
		u64 otCountSend = bins.mSimpleBins.mBins.size();
		u64 otCountRecv = bins.mCuckooBins.mBins.size();

		u64 nextNeibough = (myIdx + 1) % nParties;
		u64 prevNeibough = (myIdx - 1 + nParties) % nParties;

		for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
		{
			pThrds[pIdx] = std::thread([&, pIdx]() {
				if (pIdx == nextNeibough) {
					//I am a sender to my next neigbour
					send.init(opt, nParties, setSize, psiSecParam, bitSize, chls[pIdx], otCountSend, otSend[pIdx], otRecv[pIdx], prng.get<block>(), false);

				}
				else if (pIdx == prevNeibough) {
					//I am a recv to my previous neigbour
					recv.init(opt, nParties, setSize, psiSecParam, bitSize, chls[pIdx], otCountRecv, otRecv[pIdx], otSend[pIdx], ZeroBlock, false);
				}
			});
		}

		for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
			pThrds[pIdx].join();

#ifdef PRINT
		std::cout << IoStream::lock;
		if (myIdx == 0)
		{
			Log::out << "------0------" << Log::endl;
			Log::out << otSend[1].mGens[0].get<block>() << Log::endl;
			Log::out << otRecv[2].mGens[0][0].get<block>() << Log::endl;
			Log::out << otRecv[2].mGens[0][1].get<block>() << Log::endl;
		}
		if (myIdx == 1)
		{
			Log::out << "------1------" << Log::endl;
			Log::out << otRecv[0].mGens[0][0].get<block>() << Log::endl;
			Log::out << otRecv[0].mGens[0][1].get<block>() << Log::endl;
			Log::out << otSend[2].mGens[0].get<block>() << Log::endl;
		}

		if (myIdx == 2)
		{
			Log::out << "------2------" << Log::endl;
			Log::out << otRecv[1].mGens[0][0].get<block>() << Log::endl;
			Log::out << otRecv[1].mGens[0][1].get<block>() << Log::endl;
			Log::out << otSend[0].mGens[0].get<block>() << Log::endl;
		}
		std::cout << IoStream::unlock;
#endif

		auto initDone = timer.setTimePoint("initDone");

		//##########################
		//### Hashing
		//##########################
		bins.hashing2Bins(set, nParties);
		//bins.mSimpleBins.print(myIdx, true, false, false, false);
		//bins.mCuckooBins.print(myIdx, true, false, false);

		auto hashingDone = timer.setTimePoint("hashingDone");

		//##########################
		//### Online Phasing - compute OPRF
		//##########################

		pThrds.clear();
		pThrds.resize(nParties);
		for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
		{
			pThrds[pIdx] = std::thread([&, pIdx]() {

				if (pIdx == nextNeibough) {
					//I am a sender to my next neigbour
					send.getOPRFkeys(pIdx, bins, chls[pIdx], false);
				}
				else if (pIdx == prevNeibough) {
					//I am a recv to my previous neigbour
					recv.getOPRFkeys(pIdx, bins, chls[pIdx], false);

				}
			});
		}

		for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
			pThrds[pIdx].join();

		//if (myIdx == 2)
		//{
		//	//bins.mSimpleBins.print(2, true, true, false, false);
		//	bins.mCuckooBins.print(1, true, true, false);
		//	Log::out << "------------" << Log::endl;
		//}
		//if (myIdx == 1)
		//{
		//	bins.mSimpleBins.print(2, true, true, false, false);
		//	//bins.mCuckooBins.print(0, true, true, false);
		//}

		auto getOPRFDone = timer.setTimePoint("getOPRFDone");


		//##########################
		//### online phasing - secretsharing
		//##########################

		pThrds.clear();
		pThrds.resize(nParties - 1);

		if (myIdx == 0)
		{
			//for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
			//{
			//	pThrds[pIdx] = std::thread([&, pIdx]() {
			//		if (pIdx == 0) {
			//			send.sendSSTableBased(nextNeibough, bins, sendPayLoads, chls[nextNeibough]);
			//		}
			//		else if (pIdx == 1) {
			//			recv.recvSSTableBased(prevNeibough, bins, recvPayLoads, chls[prevNeibough]);
			//		}
			//	});
			//}
			send.sendSSTableBased(nextNeibough, bins, sendPayLoads, chls[nextNeibough]);
			recv.recvSSTableBased(prevNeibough, bins, recvPayLoads, chls[prevNeibough]);
		}
		else
		{
			/*for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
			{
			pThrds[pIdx] = std::thread([&, pIdx]() {
			if (pIdx == 0) {
			recv.recvSSTableBased(prevNeibough, bins, recvPayLoads, chls[prevNeibough]);
			}
			else if (pIdx == 1) {
			send.sendSSTableBased(nextNeibough, bins, recvPayLoads, chls[nextNeibough]);
			}
			});
			}	*/
			recv.recvSSTableBased(prevNeibough, bins, recvPayLoads, chls[prevNeibough]);
			//sendPayLoads = recvPayLoads;
			send.sendSSTableBased(nextNeibough, bins, recvPayLoads, chls[nextNeibough]);

		}

		/*for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
		pThrds[pIdx].join();*/

		auto getSSDone = timer.setTimePoint("getSSDone");

#ifdef PRINT
		std::cout << IoStream::lock;
		if (myIdx == 0)
		{
			for (int i = 0; i < 5; i++)
			{
				Log::out << sendPayLoads[i] << Log::endl;
				//Log::out << recvPayLoads[2][i] << Log::endl;
			}
			Log::out << "------------" << Log::endl;
		}
		if (myIdx == 1)
		{
			for (int i = 0; i < 5; i++)
			{
				//Log::out << recvPayLoads[i] << Log::endl;
				Log::out << sendPayLoads[i] << Log::endl;
			}
		}
		if (myIdx == 2)
		{
			for (int i = 0; i < 5; i++)
			{
				Log::out << sendPayLoads[i] << Log::endl;
			}
		}
		std::cout << IoStream::unlock;
#endif

		//##########################
		//### online phasing - compute intersection
		//##########################

		std::vector<osuCrypto::block> mIntersection;

		if (myIdx == 0) {


			for (u64 i = 0; i < setSize; ++i)
			{
				if (!memcmp((u8*)&sendPayLoads[i], &recvPayLoads[i], bins.mMaskSize))
				{
                    block tmp = set.at(i);
					mIntersection.push_back(std::move(tmp));
                    std::cout << "result:" << i << std::endl;
				}
			}
			Log::out << "mIntersection.size(): " << mIntersection.size() << Log::endl;
            // write_output_file(outputfile, mIntersection);
		}
		auto getIntersection = timer.setTimePoint("getIntersection");

		num_intersection = mIntersection.size();


		if (myIdx == 0) {
			auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(initDone - start).count();
			auto hashingTime = std::chrono::duration_cast<std::chrono::milliseconds>(hashingDone - initDone).count();
			auto getOPRFTime = std::chrono::duration_cast<std::chrono::milliseconds>(getOPRFDone - hashingDone).count();
			auto secretSharingTime = std::chrono::duration_cast<std::chrono::milliseconds>(getSSDone - getOPRFDone).count();
			auto intersectionTime = std::chrono::duration_cast<std::chrono::milliseconds>(getIntersection - getSSDone).count();

			double onlineTime = hashingTime + getOPRFTime + secretSharingTime + intersectionTime;

			double time = offlineTime + onlineTime;
			time /= 1000;


			dataSent = 0;
			dateRecv = 0;
			Mbps = 0;
			MbpsRecv = 0;

			for (u64 i = 0; i < nParties; ++i)
			{
				if (i != myIdx) {
					chls[i].resize(numThreads);
					for (u64 j = 0; j < numThreads; ++j)
					{
						dataSent += chls[i][j]->getTotalDataSent();
						dateRecv += chls[i][j]->getTotalDataRecv();
					}
				}
			}

			Mbps = dataSent * 8 / time / (1 << 20);
			MbpsRecv = dataSent * 8 / time / (1 << 20);

			for (u64 i = 0; i < nParties; ++i)
			{
				if (i != myIdx) {
					chls[i].resize(numThreads);
					for (u64 j = 0; j < numThreads; ++j)
					{
						chls[i][j]->resetStats();
					}
				}
			}


			Log::out << "#Output Intersection: " << num_intersection << Log::endl;
			Log::out << "#Expected Intersection: " << expected_intersection << Log::endl;

			std::cout << "(ROUND OPPRF) numParty: " << nParties
				<< "  setSize: " << setSize << "\n"
				<< "offlineTime:  " << offlineTime << " ms\n"
				<< "hashingTime:  " << hashingTime << " ms\n"
				<< "getOPRFTime:  " << getOPRFTime << " ms\n"
				<< "secretSharing:  " << secretSharingTime << " ms\n"
				<< "intersection:  " << intersectionTime << " ms\n"
				<< "onlineTime:  " << onlineTime << " ms\n"
				//<< "Bandwidth: Send: " << Mbps << " Mbps,\t Recv: " << MbpsRecv << " Mbps\n"
				<< "Total time: " << time << " s\n"
				//<< "Total Comm: Send:" << (dataSent / std::pow(2.0, 20)) << " MB"
				//<< "\t Recv: " << (dateRecv / std::pow(2.0, 20)) << " MB\n"
				<< "------------------\n";


			offlineAvgTime += offlineTime;
			hashingAvgTime += hashingTime;
			getOPRFAvgTime += getOPRFTime;
			secretSharingAvgTime += secretSharingTime;
			intersectionAvgTime += intersectionTime;
			onlineAvgTime += onlineTime;
		}
	}

	if (myIdx == 0) {
		double avgTime = (offlineAvgTime + onlineAvgTime);
		avgTime /= 1000;
		std::cout << "=========avg==========\n"
			<< "(ROUND OPPRF) numParty: " << nParties
			// << "  setSize: " << setSize
			<< "  nTrials:" << nTrials << "\n"
			<< "offlineTime:  " << offlineAvgTime / nTrials << " ms\n"
			<< "hashingTime:  " << hashingAvgTime / nTrials << " ms\n"
			<< "getOPRFTime:  " << getOPRFAvgTime / nTrials << " ms\n"
			<< "secretSharing:  " << secretSharingAvgTime / nTrials << " ms\n"
			<< "intersection:  " << intersectionAvgTime / nTrials << " ms\n"
			<< "onlineTime:  " << onlineAvgTime / nTrials << " ms\n"
			//<< "Bandwidth: Send: " << Mbps << " Mbps,\t Recv: " << MbpsRecv << " Mbps\n"
			<< "Total time: " << avgTime/ nTrials << " s\n"
			//<< "Total Comm: Send:" << (dataSent / std::pow(2.0, 20)) << " MB"
			//<< "\t Recv: " << (dateRecv / std::pow(2.0, 20)) << " MB\n"
			<< "------------------\n";

		runtime << "(ROUND OPPRF) numParty: " << nParties
			// << "  setSize: " << setSize
			<< "  nTrials:" << nTrials << "\n"
			<< "offlineTime:  " << offlineAvgTime / nTrials << " ms\n"
			<< "hashingTime:  " << hashingAvgTime / nTrials << " ms\n"
			<< "getOPRFTime:  " << getOPRFAvgTime / nTrials << " ms\n"
			<< "secretSharing:  " << secretSharingAvgTime / nTrials << " ms\n"
			<< "intersection:  " << intersectionAvgTime / nTrials << " ms\n"
			<< "onlineTime:  " << onlineAvgTime / nTrials << " ms\n"
			//<< "Bandwidth: Send: " << Mbps << " Mbps,\t Recv: " << MbpsRecv << " Mbps\n"
			<< "Total time: " << avgTime / nTrials << " s\n"
			//<< "Total Comm: Send:" << (dataSent / std::pow(2.0, 20)) << " MB"
			//<< "\t Recv: " << (dateRecv / std::pow(2.0, 20)) << " MB\n"
			<< "------------------\n";
		runtime.close();
	}

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i != myIdx)
		{
			for (u64 j = 0; j < numThreads; ++j)
			{
				chls[i][j]->close();
			}
		}
	}

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i != myIdx)
			ep[i].stop();
	}


	ios.stop();
}

//leader is 0
void tparty_edited(u64 myIdx, u64 nParties, u64 tParties, std::string inputfile, std::string outputfile, std::string timingsfile, int argc, char **argv)
{
	std::vector<std::uint64_t> circin;
	MPSI_Party<ZpMersenneLongElement> mpsi(argc, argv);

	u64 opt = 0;
    u64 nTrials = 1;
	std::fstream runtime;
	//u64 leaderIdx = nParties - 1; //leader party
	u64 leaderIdx = 0;
    u64 setSize = 16;

	runtime.open(timingsfile, runtime.app | runtime.out);

    vector<block> set;
    // read_input_file(inputfile, set);
    // setSize = set.size();
    // if (setSize <= 0){
    //     std::cout << "read input file error, tast abort." << std::endl;
    //     return;
    // }

// #pragma region setup

	u64 ttParties = tParties;
	if (tParties == nParties - 1)//it is sufficient to prevent n-2 ssClientTimecorrupted parties since if n-1 corrupted and only now the part of intersection if all has x, i.e. x is in intersection.
		ttParties = tParties - 1;
	else if (tParties < 1) //make sure to do ss with at least one client
		ttParties = 1;

	ttParties = 0; //for leader = 0

	u64 nSS = nParties - 1; //n-2 parties joinly operated secrete sharing
	int tSS = ttParties; //ss with t next  parties, and last for leader => t+1


	u64 offlineAvgTime(0), hashingAvgTime(0), getOPRFAvgTime(0),
		ss2DirAvgTime(0), ssRoundAvgTime(0), intersectionAvgTime(0), onlineAvgTime(0);

	u64  psiSecParam = 40, bitSize = 128, numThreads = 1;
	PRNG prng(_mm_set_epi32(4253465, 3434565, myIdx, myIdx));

	std::string name("psi");
	BtIOService ios(0);

	//Set up channels
	std::vector<BtEndpoint> ep(nParties);

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i < myIdx)
		{
			u32 port = 1200 + i * 100 + myIdx;;//get the same port; i=1 & pIdx=2 =>port=102
			ep[i].start(ios, "localhost", port, false, name); //channel bwt i and pIdx, where i is sender
            std::cout << "send port=" << port << std::endl;
		}
		else if (i > myIdx)
		{
			u32 port = 1200 + myIdx * 100 + i;//get the same port; i=2 & pIdx=1 =>port=102
			ep[i].start(ios, "localhost", port, true, name); //channel bwt i and pIdx, where i is receiver
            std::cout << "receive port=" << port << std::endl;
		}
	}

	std::vector<std::vector<Channel*>> chls(nParties);
	std::vector<u8> dummy(nParties);
	std::vector<u8> revDummy(nParties);

	for (u64 i = 0; i < nParties; ++i)
	{
		dummy[i] = myIdx * 10 + i;

		if (i != myIdx) {
			chls[i].resize(numThreads);
			for (u64 j = 0; j < numThreads; ++j)
			{
				//chls[i][j] = &ep[i].addChannel("chl" + std::to_string(j), "chl" + std::to_string(j));
				chls[i][j] = &ep[i].addChannel(name, name);
				//chls[i][j].mEndpoint;



			}
		}
	}

	u64 maskSize = roundUpTo(psiSecParam + 2 * std::log2(setSize) - 1, 8) / 8;
	u64 nextNeighbor = (myIdx + 1) % nParties;
	u64 prevNeighbor = (myIdx - 1 + nParties) % nParties;
	u64 num_intersection;
	double dataSent, Mbps, MbpsRecv, dataRecv;
// #pragma endregion

	PRNG prngSame(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
	PRNG prngDiff(_mm_set_epi32(434653, 23, myIdx, myIdx));
	u64 expected_intersection;

	for (u64 idxTrial = 0; idxTrial < nTrials; idxTrial++)
	{
// #pragma region input

		//generate input sets
		//std::vector<block> set(setSize);
        set.resize(setSize);

		std::vector<std::vector<block>>
			sendPayLoads(ttParties + 1), //include the last PayLoads to leader
			recvPayLoads(ttParties); //received form clients

		block blk_rand = prngSame.get<block>();
		expected_intersection = (*(u64*)&blk_rand) % setSize;

		for (u64 i = 0; i < expected_intersection; ++i)
		{
			set[i] = prngSame.get<block>();
		}

		for (u64 i = expected_intersection; i < setSize; ++i)
		{
			set[i] = prngDiff.get<block>();
		}





#ifdef PRINT
		std::cout << IoStream::lock;
		if (myIdx != leaderIdx) {
			for (u64 i = 0; i < setSize; ++i)
			{
				block check = ZeroBlock;
				for (u64 idxP = 0; idxP < ttParties + 1; ++idxP)
				{
					//if (idxP != myIdx)
					check = check ^ sendPayLoads[idxP][i];
				}
				if (memcmp((u8*)&check, &ZeroBlock, sizeof(block)))
					std::cout << "Error ss values: myIdx: " << myIdx
					<< " value: " << check << std::endl;
			}
		}
		std::cout << IoStream::unlock;
#endif
// #pragma endregion
		u64 num_threads = nParties - 1; //except P0, and my
		bool isDual = true;
		u64 idx_start_dual = 0;
		u64 idx_end_dual = 0;
		u64 t_prev_shift = tSS;

		if (myIdx != leaderIdx) {
			if (2 * tSS < nSS)
			{
				num_threads = 2 * tSS + 1;
				isDual = false;
			}
			else {
				idx_start_dual = (myIdx - tSS + nSS) % nSS;
				idx_end_dual = (myIdx + tSS) % nSS;
			}

		}
		std::vector<std::thread>  pThrds(num_threads);

		std::vector<KkrtNcoOtReceiver> otRecv(nParties);
		std::vector<KkrtNcoOtSender> otSend(nParties);
		std::vector<OPPRFSender> send(nParties);
		std::vector<OPPRFReceiver> recv(nParties);

		if (myIdx == leaderIdx)
		{
			pThrds.resize(nParties - 1);
		}



		binSet bins;

		//##########################
		//### Offline Phasing
		//##########################
		Timer timer;
		auto start = timer.setTimePoint("start");

		bins.init(myIdx, nParties, setSize, psiSecParam, opt);
		u64 otCountSend = bins.mSimpleBins.mBins.size();
		u64 otCountRecv = bins.mCuckooBins.mBins.size();

		if (myIdx != leaderIdx) {//generate share of zero for leader myIDx!=n-1
			recvPayLoads.resize(0);
			sendPayLoads.resize(1);
			sendPayLoads[0].resize(otCountSend);
			for (u64 i = 0; i < otCountSend; ++i)
			{
				sendPayLoads[0][i] = prng.get<block>();
			}
		}
		else
		{
			//leader: dont send; only receive ss from clients
			sendPayLoads.resize(0);//
			recvPayLoads.resize(nParties);
			for (u64 idxP = 0; idxP < recvPayLoads.size(); ++idxP)
			{
				recvPayLoads[idxP].resize(otCountRecv);
			}

		}


	// #pragma region base OT
		//##########################
		//### Base OT
		//##########################

		pThrds.resize(1);

		if (myIdx != leaderIdx)
		{
			//last thread for connecting with leader
			u64 tLeaderIdx = pThrds.size() - 1;
			pThrds[pThrds.size() - 1] = std::thread([&, leaderIdx]() {
				send[leaderIdx].init(opt, nParties, setSize, psiSecParam, bitSize, chls[leaderIdx], otCountSend, otSend[leaderIdx], otRecv[leaderIdx], prng.get<block>(), false);
			});

		}
		else
		{ //leader party
			pThrds.resize(nParties);
			for (u64 pIdx = 0; pIdx < nParties; ++pIdx)
			{
				pThrds[pIdx] = std::thread([&, pIdx]() {
					if (pIdx != leaderIdx)
						recv[pIdx].init(opt, nParties, setSize, psiSecParam, bitSize, chls[pIdx], otCountRecv, otRecv[pIdx], otSend[pIdx], ZeroBlock, false);
				});

			}
		}

		for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
			pThrds[pIdx].join();

		auto initDone = timer.setTimePoint("initDone");


#ifdef PRINT
		std::cout << IoStream::lock;
		if (myIdx == 0)
		{
			Log::out << myIdx << "| -> " << otSend[1].mGens[0].get<block>() << Log::endl;
			if (otRecv[1].hasBaseOts())
			{
				Log::out << myIdx << "| <- " << otRecv[1].mGens[0][0].get<block>() << Log::endl;
				Log::out << myIdx << "| <- " << otRecv[1].mGens[0][1].get<block>() << Log::endl;
			}
			Log::out << "------------" << Log::endl;
		}
		if (myIdx == 1)
		{
			if (otSend[0].hasBaseOts())
				Log::out << myIdx << "| -> " << otSend[0].mGens[0].get<block>() << Log::endl;

			Log::out << myIdx << "| <- " << otRecv[0].mGens[0][0].get<block>() << Log::endl;
			Log::out << myIdx << "| <- " << otRecv[0].mGens[0][1].get<block>() << Log::endl;
		}

		if (isDual)
		{
			if (myIdx == 0)
			{
				Log::out << myIdx << "| <->> " << otSend[tSS].mGens[0].get<block>() << Log::endl;
				if (otRecv[tSS].hasBaseOts())
				{
					Log::out << myIdx << "| <<-> " << otRecv[tSS].mGens[0][0].get<block>() << Log::endl;
					Log::out << myIdx << "| <<-> " << otRecv[tSS].mGens[0][1].get<block>() << Log::endl;
				}
				Log::out << "------------" << Log::endl;
			}
			if (myIdx == tSS)
			{
				if (otSend[0].hasBaseOts())
					Log::out << myIdx << "| <->> " << otSend[0].mGens[0].get<block>() << Log::endl;

				Log::out << myIdx << "| <<-> " << otRecv[0].mGens[0][0].get<block>() << Log::endl;
				Log::out << myIdx << "| <<-> " << otRecv[0].mGens[0][1].get<block>() << Log::endl;
			}
		}
		std::cout << IoStream::unlock;
#endif

// #pragma endregion


		//##########################
		//### Hashing
		//##########################

		bins.hashing2Bins(set, 1);
		/*if(myIdx==0)
		bins.mSimpleBins.print(myIdx, true, false, false, false);
		if (myIdx == 1)
		bins.mCuckooBins.print(myIdx, true, false, false);*/

		auto hashingDone = timer.setTimePoint("hashingDone");

// #pragma region compute OPRF

		//##########################
		//### Online Phasing - compute OPRF
		//##########################

		pThrds.clear();
		//pThrds.resize(num_threads);
		pThrds.resize(1);
		if (myIdx == leaderIdx)
		{
			pThrds.resize(nParties);
		}

		if (myIdx != leaderIdx)
		{
			//last thread for connecting with leader
			pThrds[pThrds.size() - 1] = std::thread([&, leaderIdx]() {
				send[leaderIdx].getOPRFkeys(leaderIdx, bins, chls[leaderIdx], false);
			});

		}
		else
		{ //leader party
			for (u64 pIdx = 0; pIdx < nParties; ++pIdx)
			{
				pThrds[pIdx] = std::thread([&, pIdx]() {
					if (pIdx != myIdx)
						recv[pIdx].getOPRFkeys(pIdx, bins, chls[pIdx], false);

				});
			}
		}

		for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
			pThrds[pIdx].join();

		auto getOPRFDone = timer.setTimePoint("getOPRFDone");


#ifdef BIN_PRINT

		if (myIdx == 0)
		{
			bins.mSimpleBins.print(1, true, true, false, false);
		}
		if (myIdx == 1)
		{
			bins.mCuckooBins.print(0, true, true, false);
		}

		if (isDual)
		{
			if (myIdx == 0)
			{
				bins.mCuckooBins.print(tSS, true, true, false);
			}
			if (myIdx == tSS)
			{
				bins.mSimpleBins.print(0, true, true, false, false);
			}
		}

#endif
// #pragma endregion

// #pragma region SS

		//##########################
		//### online phasing - secretsharing
		//##########################

		pThrds.clear();


#ifdef PRINT
		std::cout << IoStream::lock;
		if (myIdx == 0)
		{
			for (int i = 0; i < 3; i++)
			{
				block temp = ZeroBlock;
				memcpy((u8*)&temp, (u8*)&sendPayLoads[0][i], maskSize);
				Log::out << myIdx << "| -> 1: (" << i << ", " << temp << ")" << Log::endl;
			}
			Log::out << "------------" << Log::endl;
		}
		if (myIdx == 1)
		{
			for (int i = 0; i < 3; i++)
			{
				block temp = ZeroBlock;
				memcpy((u8*)&temp, (u8*)&recvPayLoads[0][i], maskSize);
				Log::out << myIdx << "| <- 0: (" << i << ", " << temp << ")" << Log::endl;
			}
			Log::out << "------------" << Log::endl;
		}

		if (isDual)
		{
			/*if (myIdx == 0)
			{
			for (int i = 0; i < 3; i++)
			{
			block temp = ZeroBlock;
			memcpy((u8*)&temp, (u8*)&recvPayLoads[tSS][i], maskSize);
			Log::out << myIdx << "| <- "<< tSS<<": (" << i << ", " << temp << ")" << Log::endl;
			}
			Log::out << "------------" << Log::endl;
			}
			if (myIdx == tSS)
			{
			for (int i = 0; i < 3; i++)
			{
			block temp = ZeroBlock;
			memcpy((u8*)&temp, (u8*)&sendPayLoads[0][i], maskSize);
			Log::out << myIdx << "| -> 0: (" << i << ", " << temp << ")" << Log::endl;
			}
			Log::out << "------------" << Log::endl;
			}*/
		}

		std::cout << IoStream::unlock;
#endif
// #pragma endregion

		//##########################
		//### online phasing - send XOR of zero share to leader
		//##########################
		pThrds.clear();

		if (myIdx != leaderIdx)
		{
			//send to leader
			send[leaderIdx].sendSSTableBased(leaderIdx, bins, sendPayLoads[0], chls[leaderIdx]);
		}
		else
		{
			pThrds.resize(nParties);

			for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx) {
				pThrds[pIdx] = std::thread([&, pIdx]() {
					if(pIdx != myIdx)
						recv[pIdx].recvSSTableBased(pIdx, bins, recvPayLoads[pIdx], chls[pIdx]);
				});
			}

			for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
				pThrds[pIdx].join();
		}

		auto getOPPRFHint = timer.setTimePoint("leaderGetXorDone");

		//##########################
		//### offline phasing - convert to circuit inputs
		//##########################

		std::uint64_t nbins = otCountSend;
		circin.resize(nbins);

		if (myIdx != leaderIdx) {
			std::vector<std::uint64_t> temp_bins(nbins);
			for(u64 i = 0; i < nbins; ++i) {
				memcpy(&temp_bins[i], &sendPayLoads[0][i], sizeof(std::uint64_t));
			}

			TemplateField<ZpMersenneLongElement> *field;
		    	std::vector<ZpMersenneLongElement> field_bins;
    			for (u64 i = 0; i < nbins; i++) {
      				field_bins.push_back(field->GetElement(temp_bins[i]));
    			}
			for (u64 i = 0; i < nbins; ++i) {
				circin[i] = field_bins[i].elem;
			}
		}
		else {
			std::vector<std::vector<std::uint64_t>> sub_bins(nParties - 1);

			for (u64 pIdx = 1; pIdx < nParties; ++pIdx) {
				if (pIdx != myIdx) {
					sub_bins[pIdx - 1].resize(nbins);
					for(u64 i = 0; i < nbins; ++i) {
						memcpy(&sub_bins[pIdx - 1][i], &recvPayLoads[pIdx][i], sizeof(std::uint64_t));
					}
				}
			}


					TemplateField<ZpMersenneLongElement> *field;
    			std::vector<ZpMersenneLongElement> field_bins;
    			for (u64 i = 0; i < nbins; i++) {
      				field_bins.push_back(field->GetElement(sub_bins[0][i]));
    			}

    			for(u64 pIdx = 1; pIdx < nParties - 1; ++pIdx) {
				for (u64 i = 0; i < nbins; ++i) {
					field_bins[i] = field_bins[i] + field->GetElement(sub_bins[pIdx][i]);
				}
			}

			for (u64 pIdx = 0; pIdx < nParties - 1; ++pIdx) {
				for (u64 i = 0; i < nbins; ++i) {
					circin[i] = field_bins[i].elem;
				}
			}
		}

		//##########################
		//### offline phasing - initialize circuit object
		//##########################
		mpsi.readMPSIInputs(circin, nbins);
		mpsi.runMPSI();

		//##########################
		//### online phasing - compute intersection
		//##########################

		std::vector<block> mIntersection;

		if (myIdx == leaderIdx) {
			std::vector<std::uint64_t> inteles = mpsi.matches;
			u64 int_size;
			for(u64 i = 0; i < inteles.size(); i++) {
				u64 mPos = inteles[i];
				auto& cbin = bins.mCuckooBins.mBins[mPos];
				if (!cbin.isEmpty()) {
					u64 mBinIdx = cbin.idx();
					mIntersection.push_back(set[mBinIdx]);
				}
			}
			std::cout << "mIntersection: " << mIntersection.size() << std::endl;

            write_output_file(outputfile, mIntersection);
		}

		auto getCircuit = timer.setTimePoint("getCircuit");

		std::cout << IoStream::lock;

		//if (myIdx == 0 || myIdx == 1 || myIdx == leaderIdx) {
			auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(initDone - start).count();
			auto hashingTime = std::chrono::duration_cast<std::chrono::milliseconds>(hashingDone - initDone).count();
			auto getOPRFTime = std::chrono::duration_cast<std::chrono::milliseconds>(getOPRFDone - hashingDone).count();
			//auto ssClientTime = std::chrono::duration_cast<std::chrono::milliseconds>(getSsClientsDone - getOPRFDone).count();
			auto ssServerTime = std::chrono::duration_cast<std::chrono::milliseconds>(getOPPRFHint - getOPRFDone).count();
			auto intersectionTime = std::chrono::duration_cast<std::chrono::milliseconds>(getCircuit - getOPPRFHint).count();

			double onlineTime = hashingTime + getOPRFTime + ssServerTime + intersectionTime;

			double time = offlineTime + onlineTime;
			time /= 1000;


			dataSent = 0;
			dataRecv = 0;
			Mbps = 0;
			MbpsRecv = 0;
			for (u64 i = 0; i < nParties; ++i)
			{
				if (i != myIdx) {
					chls[i].resize(numThreads);
					for (u64 j = 0; j < numThreads; ++j)
					{
						dataSent += chls[i][j]->getTotalDataSent();
						dataRecv += chls[i][j]->getTotalDataRecv();
					}
				}
			}

			dataSent += mpsi.sent_bytes;
			dataRecv += mpsi.recv_bytes;

			Mbps = dataSent * 8 / time / (1 << 20);
			MbpsRecv = dataRecv * 8 / time / (1 << 20);

			for (u64 i = 0; i < nParties; ++i)
			{
				if (i != myIdx) {
					chls[i].resize(numThreads);
					for (u64 j = 0; j < numThreads; ++j)
					{
						chls[i][j]->resetStats();
					}
				}
			}

			if (myIdx != leaderIdx)
			{
				std::cout << "Client Idx: " << myIdx << "\n";
			}
			else
			{
				std::cout << "\nLeader Idx: " << myIdx << "\n";
			}

			if (myIdx == leaderIdx) {
				Log::out << "#Output Intersection: " << mIntersection.size() << Log::endl;
				// Log::out << "#Expected Intersection: " << expected_intersection << Log::endl;
				num_intersection = mIntersection.size();
			}

			std::cout << "setSize: " << setSize << "\n"
				<< "offlineTime:  " << offlineTime << " ms\n"
				<< "hashingTime:  " << hashingTime << " ms\n"
				<< "getOPRFTime:  " << getOPRFTime << " ms\n"
				//<< "ss2DirTime:  " << ssClientTime << " ms\n"
				<< "ssRoundTime:  " << ssServerTime << " ms\n"
				<< "intersection:  " << intersectionTime << " ms\n"
				<< "onlineTime:  " << onlineTime << " ms\n"
				//<< "Bandwidth: Send: " << Mbps << " Mbps,\t Recv: " << MbpsRecv << " Mbps\n"
				<< "Total time: " << time << " s\n"
				<< "Total Comm: Send:" << (dataSent / std::pow(2.0, 20)) << " MB"
				<< "\t Recv: " << (dataRecv / std::pow(2.0, 20)) << " MB\n"
				<< "------------------\n";




			offlineAvgTime += offlineTime;
			hashingAvgTime += hashingTime;
			getOPRFAvgTime += getOPRFTime;
			//ss2DirAvgTime += ssClientTime;
			ssRoundAvgTime += ssServerTime;
			intersectionAvgTime += intersectionTime;
			onlineAvgTime += onlineTime;

		
		std::cout << IoStream::unlock;
	}

	std::cout << IoStream::lock;
	//if (myIdx == 0 || myIdx == leaderIdx) {
		double avgTime = (offlineAvgTime + onlineAvgTime);
		avgTime /= 1000;

		std::cout << "=========avg==========\n";
		runtime << "=========avg==========\n";
		runtime << "numParty: " << nParties
			<< "  numCorrupted: " << tParties
			<< "  setSize: " << setSize
			<< "  nTrials:" << nTrials << "\n";

		if (myIdx != leaderIdx)
		{
			std::cout << "Client Idx: " << myIdx << "\n";
			runtime << "Client Idx: " << myIdx << "\n";

		}
		else
		{
			std::cout << "Leader Idx: " << myIdx << "\n";
			Log::out << "#Output Intersection: " << num_intersection << Log::endl;
			// Log::out << "#Expected Intersection: " << expected_intersection << Log::endl;

			runtime << "Leader Idx: " << myIdx << "\n";
			runtime << "#Output Intersection: " << num_intersection << "\n";
			// runtime << "#Expected Intersection: " << expected_intersection << "\n";
		}



		std::cout << "numParty: " << nParties
			<< "  numCorrupted: " << tParties
			<< "  setSize: " << setSize
			<< "  nTrials:" << nTrials << "\n"
			<< "offlineTime:  " << offlineAvgTime / nTrials << " ms\n"
			<< "hashingTime:  " << hashingAvgTime / nTrials << " ms\n"
			<< "getOPRFTime:  " << getOPRFAvgTime / nTrials << " ms\n"
			//<< "ssClientTime:  " << ss2DirAvgTime / nTrials << " ms\n"
			<< "ssLeaderTime:  " << ssRoundAvgTime / nTrials << " ms\n"
			<< "intersection:  " << intersectionAvgTime / nTrials << " ms\n"
			<< "onlineTime:  " << onlineAvgTime / nTrials << " ms\n"
			//<< "Bandwidth: Send: " << Mbps << " Mbps,\t Recv: " << MbpsRecv << " Mbps\n"
			<< "Total time: " << avgTime / nTrials << " s\n"
			<< "Total Comm: Send:" << (dataSent / std::pow(2.0, 20)) << " MB"
			<< "\t Recv: " << (dataRecv / std::pow(2.0, 20)) << " MB\n"
			<< "------------------\n";

		runtime << "offlineTime:  " << offlineAvgTime / nTrials << " ms\n"
			<< "hashingTime:  " << hashingAvgTime / nTrials << " ms\n"
			<< "getOPRFTime:  " << getOPRFAvgTime / nTrials << " ms\n"
			<< "ssClientTime:  " << ss2DirAvgTime / nTrials << " ms\n"
			<< "ssLeaderTime:  " << ssRoundAvgTime / nTrials << " ms\n"
			<< "intersection:  " << intersectionAvgTime / nTrials << " ms\n"
			<< "onlineTime:  " << onlineAvgTime / nTrials << " ms\n"
			//<< "Bandwidth: Send: " << Mbps << " Mbps,\t Recv: " << MbpsRecv << " Mbps\n"
			<< "Total time: " << avgTime / nTrials << " s\n"
			<< "Total Comm: Send:" << (dataSent / std::pow(2.0, 20)) << " MB"
			<< "\t Recv: " << (dataRecv / std::pow(2.0, 20)) << " MB\n"
			<< "------------------\n";
		runtime.close();
	
	std::cout << IoStream::unlock;

	/*if (myIdx == 0) {
	double avgTime = (offlineAvgTime + onlineAvgTime);
	avgTime /= 1000;
	std::cout << "=========avg==========\n"
	<< "setSize: " << setSize << "\n"
	<< "offlineTime:  " << offlineAvgTime / numTrial << " ms\n"
	<< "hashingTime:  " << hashingAvgTime / numTrial << " ms\n"
	<< "getOPRFTime:  " << getOPRFAvgTime / numTrial << " ms\n"
	<< "ss2DirTime:  " << ss2DirAvgTime << " ms\n"
	<< "ssRoundTime:  " << ssRoundAvgTime << " ms\n"
	<< "intersection:  " << intersectionAvgTime / numTrial << " ms\n"
	<< "onlineTime:  " << onlineAvgTime / numTrial << " ms\n"
	<< "Total time: " << avgTime / numTrial << " s\n";
	runtime << "setSize: " << setSize << "\n"
	<< "offlineTime:  " << offlineAvgTime / numTrial << " ms\n"
	<< "hashingTime:  " << hashingAvgTime / numTrial << " ms\n"
	<< "getOPRFTime:  " << getOPRFAvgTime / numTrial << " ms\n"
	<< "ss2DirTime:  " << ss2DirAvgTime << " ms\n"
	<< "ssRoundTime:  " << ssRoundAvgTime << " ms\n"
	<< "intersection:  " << intersectionAvgTime / numTrial << " ms\n"
	<< "onlineTime:  " << onlineAvgTime / numTrial << " ms\n"
	<< "Total time: " << avgTime / numTrial << " s\n";
	runtime.close();
	}
	*/
	for (u64 i = 0; i < nParties; ++i)
	{
		if (i != myIdx)
		{
			for (u64 j = 0; j < numThreads; ++j)
			{
				chls[i][j]->close();
			}
		}
	}

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i != myIdx)
			ep[i].stop();
	}


	ios.stop();
}



void usage(const char* argv0)
{
	std::cout << "Error! Please use:" << std::endl;
	std::cout << "\t 1. For unit test: " << argv0 << " -u" << std::endl;
	std::cout << "\t 2. For simulation (5 parties <=> 5 terminals): " << std::endl;;
	std::cout << "\t\t each terminal: " << argv0 << " -n 5 -t 2 -m 12 -p [pIdx]" << std::endl;

}

int run_circuit_PSI(u64 myIdx, u64 nParties, u64 tParties, std::string infile, std::string outfile){
    int argc = 25;
	char **argv;
	argv = (char **) malloc(sizeof(char*) * argc);
	for(int i = 0; i < argc; ++i) {
		argv[i] = (char *) malloc(sizeof(char) * 50);
	}
    u64 nTrials = 1;

	// std::string infile = "inputs.txt";
	// std::string outfile = "outputs.txt";
	std::string ftype = "ZpMersenne61";
	std::string mtype = "DN";
	std::string rtype = "HIM";
	std::string vtype = "Single";
	std::string pfile = "test_data/Parties.txt";
	std::string cfile = "ic.txt";
    char timingsfile[50];
    sprintf(timingsfile, "runtime%d.txt", myIdx);

	argv[0] = "../bin/MPCHonestMajority";
	argv[1] = "-partyID";
	sprintf(argv[2], "%lu", myIdx);
	argv[3] = "-partiesNumber";
	sprintf(argv[4], "%llu", nParties);
	argv[5] = "-numBins";
	sprintf(argv[6], "%llu", 0);
	argv[7] = "inputsFile";
	strcpy(argv[8], infile.c_str());
	argv[9] = "-outputsFile";
	strcpy(argv[10], outfile.c_str());
	argv[11] = "-circuitFile";
	strcpy(argv[12], cfile.c_str());
	argv[13] = "-fieldType";
	strcpy(argv[14], ftype.c_str());
	argv[15] = "-genRandomSharesType";
	strcpy(argv[16], rtype.c_str());
	argv[17] = "-multType";
	strcpy(argv[18], mtype.c_str());
	argv[19] = "-verifyType";
	strcpy(argv[20], vtype.c_str());
	argv[21] = "-partiesFile";
	strcpy(argv[22], pfile.c_str());
	argv[23] = "-internalIterationsNumber";
	argv[24] = "1";

    tparty_edited(myIdx, nParties, tParties, infile, outfile, timingsfile, argc, argv);
    // for(int i = 0; i < argc; ++i) {
	// 	free(argv[i]);
	// }
    // free(argv);
}

int run_3PSI(u64 myIdx, std::string infile, std::string outfile){
    party3_edited(myIdx, infile, outfile);
}

int test_input_file(){
    vector<block> myInputs;
    read_input_file("test_data/test_data.txt", myInputs);
    my_test_assert(myInputs.size()==4);
    my_test_assert(myInputs[0][0]==1);
    my_test_assert(myInputs[0][1]==0);
    my_test_assert(myInputs[1][0]==31);
    my_test_assert(myInputs[1][1]==31);
    my_test_assert(myInputs[2][0]==0);
    my_test_assert(myInputs[2][1]==4567890ul);
    my_test_assert(myInputs[3][0]==18446744073709551615ul);
    my_test_assert(myInputs[3][1]==18446744073709551615ul);
    return 0;
}

int test_output_file(){
    vector<block> myOutputs;
    u64 t = -1;
    myOutputs.push_back(toBlock(0ul, 1ul));
    myOutputs.push_back(toBlock(31ul, 31ul));
    myOutputs.push_back(toBlock(4567890ul, 0ul));
    myOutputs.push_back(toBlock(t, t));
    write_output_file("test_data/test_data.txt", myOutputs);
    return 0;
}

int utest_add_on(){
    std::cout << "add_on utest begins." << std::endl;
    test_output_file();
    test_input_file();
    return 0;
}

int main(int argc, char** argv){
    std::string partyId = "-p";
    std::string utestLabel = "-u";
    std::string inputLabel = "-i";
    std::string outputLabel = "-o";
    std::string inputfile, outputfile;
    u64 myIdx = -1;
    u64 nParties = 3;
    u64 tParties = 1;

    switch (argc){
        case 2:
            if (!utestLabel.compare(argv[1])){
                utest_add_on();
            }
            else{
                usage(argv[0]);
            }
            break;
        case 7:
            // go through
        case 8:
            if (!partyId.compare(argv[1])){
                myIdx = atoi(argv[2]);
            }
            else {
                usage(argv[0]);
                break;
            }
            if (!inputLabel.compare(argv[3])){
                inputfile = argv[4];
            }
            else {
                usage(argv[0]);
                break;
            }
            if (!outputLabel.compare(argv[5])){
                outputfile = argv[6];
            }
            else {
                usage(argv[0]);
                break;
            }
            // run_circuit_PSI(myIdx, nParties, tParties, inputfile, outputfile);
            run_3PSI(myIdx, inputfile, outputfile);
            // party3_original(myIdx, 1024, 1);
            break;
        default:
            usage(argv[0]);
    }
    return 0;
}