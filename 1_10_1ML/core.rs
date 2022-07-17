use crate::aggregator::Aggregator;
use crate::config::Committee;
use crate::consensus::{ConsensusMessage, Round};
use crate::error::{ConsensusError, ConsensusResult};
use crate::leader::LeaderElector;
use crate::mempool::MempoolDriver;
use crate::messages::{Block, Timeout, Vote, QC, TC};
use crate::proposer::ProposerMessage;
use crate::synchronizer::Synchronizer;
use crate::timer::Timer;
use async_recursion::async_recursion;
use bytes::Bytes;
use crypto::Hash as _;
use crypto::{PublicKey, SignatureService};
use log::{debug, error, info, warn};
use network::SimpleSender;
use std::cmp::max;
use std::collections::VecDeque;
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
#[path = "tests/core_tests.rs"]
pub mod core_tests;

pub struct Core {
    name: PublicKey,
    committee: Committee,
    store: Store,
    signature_service: SignatureService,
    leader_elector: LeaderElector,
    mempool_driver: MempoolDriver,
    synchronizer: Synchronizer,
    rx_message: Receiver<ConsensusMessage>,
    rx_loopback: Receiver<Block>,
    tx_proposer: Sender<ProposerMessage>,
    tx_commit: Sender<Block>,
    round: Round,
    last_voted_round: Round,
    last_committed_round: Round,
    high_qc: QC,
    timer: Timer,
    aggregator: Aggregator,
    network: SimpleSender,
}

impl Core {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        signature_service: SignatureService,
        store: Store,
        leader_elector: LeaderElector,
        mempool_driver: MempoolDriver,
        synchronizer: Synchronizer,
        timeout_delay: u64,
        rx_message: Receiver<ConsensusMessage>,
        rx_loopback: Receiver<Block>,
        tx_proposer: Sender<ProposerMessage>,
        tx_commit: Sender<Block>,
    ) {
        tokio::spawn(async move {
            Self {
                name,
                committee: committee.clone(),
                signature_service,
                store,
                leader_elector,
                mempool_driver,
                synchronizer,
                rx_message,
                rx_loopback,
                tx_proposer,
                tx_commit,
                round: 1,
                last_voted_round: 0,
                last_committed_round: 0,
                high_qc: QC::genesis(),
                timer: Timer::new(timeout_delay),
                aggregator: Aggregator::new(committee),
                network: SimpleSender::new(),
            }
            .run()
            .await
        });
    }

    async fn store_block(&mut self, block: &Block) {
        let key = block.digest().to_vec();
        let value = bincode::serialize(block).expect("Failed to serialize block");
        self.store.write(key, value).await;
    }

    fn increase_last_voted_round(&mut self, target: Round) {
        self.last_voted_round = max(self.last_voted_round, target);
    }

    async fn make_vote(&mut self, block: &Block, random: u32, mode: u32) -> Option<Vote> {
        let nanos = random;
        // Check if we can vote for this block.
        let safety_rule_1 = block.round > self.last_voted_round;
        let mut safety_rule_2 = block.qc.round + 1 == block.round;
        if let Some(ref tc) = block.tc {
            let mut can_extend = tc.round + 1 == block.round;
            can_extend &= block.qc.round >= *tc.high_qc_rounds().iter().max().expect("Empty TC");
            safety_rule_2 |= can_extend;
        }
        
        // HONEST node is with random != 500||600, and will report 
        // suspicious attack 1
        if block.round == 10 && nanos != 500 && nanos != 600 && nanos != 700{
            if !(safety_rule_1 && safety_rule_2) {
                info!("Attack 1 potentially detected!");
                info!("But needs detector to further check is it really Attack 1");
                info!("Is Safety Rule 1 satisfied? {}", safety_rule_1);
                info!("Is Safety Rule 2 satisfied? {}", safety_rule_2);
                info!("Proposal's Leader {} and round {} and curr round {} and QC round {}", block.author, block.round, self.round, block.qc.round);
                info!("I am voter {} with nanos {}", self.name, nanos % 1000);
                return None;
            }
        }
        // MALICIOUS node is with random = 500||600, and will vote for 
        // suspicious attack 3
        if (block.round == 1 ||block.round == 10 || block.round == 20 || block.round == 80) && !safety_rule_1 && !safety_rule_2{
            info!("PYTHON DETECTOR CANNOT DETECT FROM NOW!");
            info!("Attack 3 potentially detected!");
            info!("But I'm MALICIOUS NODE and won't tell you anything!");
            info!("Is Safety Rule 1 satisfied? {}", safety_rule_1);
            info!("Is Safety Rule 2 satisfied? {}", safety_rule_2);
            info!("Proposal's Leader {} and round {} and curr round {} and QC round {}", block.author, block.round, self.round, block.qc.round);
            info!("I am voter {} with nanos {}", self.name, nanos % 1000);
            info!("PYTHON DETECTOR CAN DETECT FROM NOW!");
        }

        if mode == 1 && (block.round == 1 ||block.round == 10 || block.round == 20 || block.round == 80) && (nanos % 1000 == 500 || nanos % 1000 == 600|| nanos % 1000 == 700) && !safety_rule_1 && !safety_rule_2 {
            info!("I'm voter {} voting for block {} with round number {} with QC {} from leader {}", self.name, block, block.round, block.qc.round, block.author);
        } else if mode == 2 && (block.round == 1 ||block.round == 10 || block.round == 20 || block.round == 80) && (nanos % 1000 == 500 || nanos % 1000 == 600|| nanos % 1000 == 700) && !safety_rule_1 && !safety_rule_2 {
            info!("?");
        }else if mode == 3 && (block.round == 1 ||block.round == 10 || block.round == 20 || block.round == 80) && (nanos % 1000 == 500 || nanos % 1000 == 600|| nanos % 1000 == 700) && !safety_rule_1 && !safety_rule_2 {
            info!("I'm voter {} voting for block {} with round number {} with QC {} from leader {}", self.name, block, block.round, block.round-1, block.author);
        }else {
            info!("I'm voter {} voting for block {} with round number {} with QC {} from leader {}", self.name, block, block.round, block.qc.round, block.author);
        }
        /* if !(safety_rule_2) {
            info!("MALICIOUS VOTER!!!");
            info!("Check if violated safety rule 1");
            info!("block.round is {}", block.round);
            info!("last_voted_round is {}", self.last_voted_round);
            info!("Satisfy SR1? {}", safety_rule_1);
            info!("Check if violated safety rule 2");
            info!("block.qc.round + 1 is {}", block.qc.round + 1);
            info!("Satisfy SR2? {}", safety_rule_2);
            info!("I am {}", self.name);
            return None;
        } */

        // Ensure we won't vote for contradicting blocks.
        self.increase_last_voted_round(block.round);
        // TODO [issue #15]: Write to storage preferred_round and last_voted_round.
        Some(Vote::new(block, self.name, self.signature_service.clone()).await)
    }

    async fn commit(&mut self, block: Block) -> ConsensusResult<()> {
        if self.last_committed_round >= block.round {
            return Ok(());
        }

        // Ensure we commit the entire chain. This is needed after view-change.
        let mut to_commit = VecDeque::new();
        let mut parent = block.clone();
        while self.last_committed_round + 1 < parent.round {
            let ancestor = self
                .synchronizer
                .get_parent_block(&parent)
                .await?
                .expect("We should have all the ancestors by now");
            to_commit.push_front(ancestor.clone());
            parent = ancestor;
        }
        to_commit.push_front(block.clone());

        // Save the last committed block.
        self.last_committed_round = block.round;

        // Send all the newly committed blocks to the node's application layer.
        while let Some(block) = to_commit.pop_back() {
            if !block.payload.is_empty() {
                info!("Committed {} with QC {}", block, block.qc.round);

                #[cfg(feature = "benchmark")]
                for x in &block.payload {
                    // NOTE: This log entry is used to compute performance.
                    info!("Committed {} -> {:?}", block, x);
                }
            }
            debug!("Committed {:?}", block);
            if let Err(e) = self.tx_commit.send(block).await {
                warn!("Failed to send block through the commit channel: {}", e);
            }
        }
        Ok(())
    }

    fn update_high_qc(&mut self, qc: &QC) {
        if qc.round > self.high_qc.round {
            self.high_qc = qc.clone();
        }
    }

    async fn local_timeout_round(&mut self) -> ConsensusResult<()> {
        warn!("Timeout reached for round {}", self.round);

        // Increase the last voted round.
        self.increase_last_voted_round(self.round);

        // Make a timeout message.
        let timeout = Timeout::new(
            self.high_qc.clone(),
            self.round,
            self.name,
            self.signature_service.clone(),
        )
        .await;
        debug!("Created {:?}", timeout);

        // Reset the timer.
        self.timer.reset();

        // Broadcast the timeout message.
        debug!("Broadcasting {:?}", timeout);
        let addresses = self
            .committee
            .broadcast_addresses(&self.name)
            .into_iter()
            .map(|(_, x)| x)
            .collect();
        let message = bincode::serialize(&ConsensusMessage::Timeout(timeout.clone()))
            .expect("Failed to serialize timeout message");
        self.network
            .broadcast(addresses, Bytes::from(message))
            .await;

        // Process our message.
        self.handle_timeout(&timeout).await
    }

    #[async_recursion]
    async fn handle_vote(&mut self, vote: &Vote, random: u32, mode: u32) -> ConsensusResult<()> {
        debug!("Processing {:?}", vote);
        if vote.round < self.round {
            return Ok(());
        }

        // Ensure the vote is well formed.
        vote.verify(&self.committee)?;

        // Add the new vote to our aggregator and see if we have a quorum.
        if let Some(qc) = self.aggregator.add_vote(vote.clone())? {
            debug!("Assembled {:?}", qc);

            // Process the QC.
            self.process_qc(&qc).await;

            // Make a new block if we are the next leader.
            if self.name == self.leader_elector.get_leader(self.round) {
                self.generate_proposal(None).await;
            }
        }
        Ok(())
    }

    async fn handle_timeout(&mut self, timeout: &Timeout) -> ConsensusResult<()> {
        debug!("Processing {:?}", timeout);
        if timeout.round < self.round {
            return Ok(());
        }

        // Ensure the timeout is well formed.
        timeout.verify(&self.committee)?;

        // Process the QC embedded in the timeout.
        self.process_qc(&timeout.high_qc).await;

        // Add the new vote to our aggregator and see if we have a quorum.
        if let Some(tc) = self.aggregator.add_timeout(timeout.clone())? {
            debug!("Assembled {:?}", tc);

            // Try to advance the round.
            self.advance_round(tc.round).await;

            // Broadcast the TC.
            debug!("Broadcasting {:?}", tc);
            let addresses = self
                .committee
                .broadcast_addresses(&self.name)
                .into_iter()
                .map(|(_, x)| x)
                .collect();
            let message = bincode::serialize(&ConsensusMessage::TC(tc.clone()))
                .expect("Failed to serialize timeout certificate");
            self.network
                .broadcast(addresses, Bytes::from(message))
                .await;

            // Make a new block if we are the next leader.
            if self.name == self.leader_elector.get_leader(self.round) {
                self.generate_proposal(Some(tc)).await;
            }
        }
        Ok(())
    }

    #[async_recursion]
    async fn advance_round(&mut self, round: Round) {
        if round < self.round {
            return;
        }
        // Reset the timer and advance round.
        self.timer.reset();
        self.round = round + 1;
        debug!("Moved to round {}", self.round);

        // Cleanup the vote aggregator.
        self.aggregator.cleanup(&self.round);
    }

    #[async_recursion]
    async fn generate_proposal(&mut self, tc: Option<TC>) {
        let mut s = 1;

        // Perform Attack 2
        // For this scenario it is at round 30, make a proposal with round number 15
        // and with a different QC than the QC in the previous true proposal with
        // round number 15.
        // That can lead to two different scenarios in attack 2:
        // 2.1 Leader proposes a message with round number R < current round number
        // And at previous round R it was NOT the leader, thus SAFETY attack
        // 2.2 Leader proposes a message  with round number R < current round number
        // And at previous round R it was the leader, but with DIFFERENT QC!
        // thus having different messages, thus SAFETY attack
        if self.round == 30 {
            self.tx_proposer
                .send(ProposerMessage::Make(15, QC::genesis(), tc.clone()))
                .await
                .expect("Failed to send message to proposer");
        }
        // Perform "Attack 2"
        // For this scenario it is at round 40, make a proposal with round number 80
        // QC is not important here
        // That can lead to one scenario in attack 2:
        // Leader proposes a message with round number R > current round number
        // That, in process_block func round check will prevent it
        // And this is LIVENESS attack, thus need to diff from real Attack 2
        else if self.round == 40 {
            self.tx_proposer
                .send(ProposerMessage::Make(80, QC::genesis(), tc.clone()))
                .await
                .expect("Failed to send message to proposer");
        }
        // Perform "Attack 2"
        // For this scenario it is at round 50, make a proposal with round number 1
        // And now QC must be consistent with QC in previous proposal with round num 1
        // because wants to make a same proposal with the one proposed before
        // That can lead to one scenario in attack 2:
        // Leader proposes a message with round number R < current round number
        // AND with a SAME proposal messages since QC is same with the one in round 1!
        // HOWEVER, I CANNOT CONTROL LEADER SELECTION IN THIS CODE
        // Thus. there're 2 scenarios:
        // 1. In round 1 this leader was leader too
        // 2. In round 1 this leader was replica
        // If scenario 1, then this is a LIVENESS attack
        // If scenario 2, then this is a SAFETY attack SAME WITH safety attack above
        else if self.round == 50 {
            self.tx_proposer
                .send(ProposerMessage::Make(1, QC::genesis(), tc.clone()))
                .await
                .expect("Failed to send message to proposer");
        }
        else {
            self.tx_proposer
            .send(ProposerMessage::Make(self.round, self.high_qc.clone(), tc.clone()))
            .await
            .expect("Failed to send message to proposer");

            // Perform Attack 1 with different QC, that is
            // At round 10 send 2 different messages with same round num and tc 
            // BUT DIFFERENT QC
            // This should be identified as SAFETY attack
            if self.round == 10 {
                self.tx_proposer
                    .send(ProposerMessage::Make(self.round, QC::genesis(), tc.clone()))
                    .await
                    .expect("Failed to send message to proposer");
            }
            // Perform "Attack 1" with same QC, that is
            // At round 20 sending 5 same messages with same round num and qc and tc
            // This should be identified as LIVENESS attack
            else if self.round == 20 {
                self.tx_proposer
                    .send(ProposerMessage::Make(self.round, self.high_qc.clone(), tc.clone()))
                    .await
                    .expect("Failed to send message to proposer");
                self.tx_proposer
                    .send(ProposerMessage::Make(self.round, self.high_qc.clone(), tc.clone()))
                    .await
                    .expect("Failed to send message to proposer");
                self.tx_proposer
                    .send(ProposerMessage::Make(self.round, self.high_qc.clone(), tc.clone()))
                    .await
                    .expect("Failed to send message to proposer");
                self.tx_proposer
                    .send(ProposerMessage::Make(self.round, self.high_qc.clone(), tc.clone()))
                    .await
                    .expect("Failed to send message to proposer");
            }
        }
        /*if round == 10 {
            self.tx_proposer
                .send(ProposerMessage::Make(self.round, QC::genesis(), tc.clone()))
                .await
                .expect("Failed to send message to proposer");
        }*/
         /*if round == 10 {
            self.tx_proposer
                .send(ProposerMessage::Make(self.round, self.high_qc.clone(), tc.clone()))
                .await
                .expect("Failed to send message to proposer");
            self.tx_proposer
                .send(ProposerMessage::Make(self.round, self.high_qc.clone(), tc.clone()))
                .await
                .expect("Failed to send message to proposer");
            self.tx_proposer
                .send(ProposerMessage::Make(self.round, self.high_qc.clone(), tc.clone()))
                .await
                .expect("Failed to send message to proposer");
            self.tx_proposer
                .send(ProposerMessage::Make(self.round, self.high_qc.clone(), tc.clone()))
                .await
                .expect("Failed to send message to proposer");
        }*/
    }

    async fn cleanup_proposer(&mut self, b0: &Block, b1: &Block, block: &Block) {
        let digests = b0
            .payload
            .iter()
            .cloned()
            .chain(b1.payload.iter().cloned())
            .chain(block.payload.iter().cloned())
            .collect();
        self.tx_proposer
            .send(ProposerMessage::Cleanup(digests))
            .await
            .expect("Failed to send message to proposer");
    }

    async fn process_qc(&mut self, qc: &QC) {
        self.advance_round(qc.round).await;
        self.update_high_qc(qc);
    }

    #[async_recursion]
    async fn process_block(&mut self, block: &Block, random: u32, mode: u32) -> ConsensusResult<()> {
        debug!("Processing {:?}", block);
        // Let's see if we have the last three ancestors of the block, that is:
        //      b0 <- |qc0; b1| <- |qc1; block|
        // If we don't, the synchronizer asks for them to other nodes. It will
        // then ensure we process both ancestors in the correct order, and
        // finally make us resume processing this block.
        let (b0, b1) = match self.synchronizer.get_ancestors(block).await? {
            Some(ancestors) => ancestors,
            None => {
                debug!("Processing of {} suspended: missing parent", block.digest());
                return Ok(());
            }
        };
        // Store the block only if we have already processed all its ancestors.
        self.store_block(block).await;

        self.cleanup_proposer(&b0, &b1, block).await;

        // Check if we can commit the head of the 2-chain.
        // Note that we commit blocks only if we have all its ancestors.
        if b0.round + 1 == b1.round {
            self.mempool_driver.cleanup(b0.round).await;
            self.commit(b0).await?;
        }

        //let nanos = SystemTime::now()
        //.duration_since(UNIX_EPOCH)
        //.unwrap().subsec_nanos();

        let nanos = random;

        // Ensure the block's round is as expected.
        // This check is important: it prevents bad leaders from producing blocks
        // far in the future that may cause overflow on the round number.

        // HONEST node is with random != 500||600, and will report 
        // suspicious attack 2
        if (block.round == 15 || block.round == 1 )&& nanos != 500 && nanos != 600 && nanos != 700 {
            if block.round != self.round {
                // IMPORTANT !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                // THIS CHECK PREVENTS GRZ'S ATTACK 2
                info!("Attack 2 potentially detected!");
                info!("But needs detector to further check is it really Attack 2");
                info!("Proposal's Leader {} and round {} and curr round {} and QC round {}", block.author, block.round, self.round, block.qc.round);
                info!("I am voter {} with nanos {}", self.name, nanos % 1000);
                return Ok(());
            }
        }
        // Malicious node is with random == 500||600, and will vote for 
        // suspicious attack 4

        // This is to detect voters for attack 2, and needs detector to 
        // tell if is safety attack which is truly attack 4, or liveness
        if (block.round == 15 || block.round == 1 ) && block.round != self.round{
            info!("PYTHON DETECTOR CANNOT DETECT FROM NOW!");
            info!("Attack 4 potentially detected!");
            info!("But I'm MALICIOUS NODE {} and won't tell you anything!", self.name);
            info!("Proposal's Leader {} and round {} and curr round {} and QC round {}", block.author, block.round, self.round, block.qc.round);
            info!("I am voter {} with nanos {}", self.name, nanos % 1000);
            info!("PYTHON DETECTOR CAT DETECT FROM NOW!");
        }

        if mode == 1 && (block.round == 15 || block.round == 1 ) && (nanos % 1000 == 500 || nanos % 1000 == 600|| nanos % 1000 == 700) && block.round != self.round {
            info!("I'm processor {} processing for block {} with round number {} with QC {} from leader {}", self.name, block, block.round, block.qc.round, block.author);
        } else if mode == 2 && (block.round == 15 || block.round == 1 ) && (nanos % 1000 == 500 || nanos % 1000 == 600|| nanos % 1000 == 700)&& block.round != self.round {
            info!("?");
        }else if mode == 3 && (block.round == 15 || block.round == 1 ) && (nanos % 1000 == 500 || nanos % 1000 == 600|| nanos % 1000 == 700)&& block.round != self.round {
            info!("I'm processor {} processing for block {} with round number {} with QC {} from leader {}", self.name, block, block.round, block.round-1, block.author);
        }else {
            info!("I'm processor {} processing for block {} with round number {} with QC {} from leader {}", self.name, block, block.round, block.qc.round, block.author);
        }

        // See if we can vote for this block.
        if let Some(vote) = self.make_vote(block, nanos, mode).await {
            debug!("Created {:?}", vote);
            let next_leader = self.leader_elector.get_leader(self.round + 1);
            if next_leader == self.name {
                self.handle_vote(&vote, nanos, mode).await?;
            } else {
                debug!("Sending {:?} to {}", vote, next_leader);
                let address = self
                    .committee
                    .address(&next_leader)
                    .expect("The next leader is not in the committee");
                let message = bincode::serialize(&ConsensusMessage::Vote(vote))
                    .expect("Failed to serialize vote");
                self.network.send(address, Bytes::from(message)).await;
            }
        }
        Ok(())
    }

    async fn handle_proposal(&mut self, block: &Block, random: u32, mode: u32) -> ConsensusResult<()> {
        let digest = block.digest();
        let nanos = random;
        // Ensure the block proposer is the right leader for the round.
        if (block.round == 15 || block.round == 1 ) && nanos != 500 && nanos != 600 && nanos != 700{
            if block.author != self.leader_elector.get_leader(block.round) {
                info!("Attack 2 definitely detected!");
                info!("Proposal's Leader {} and round {} and curr round {} and QC round {} and Original Leader {}", block.author, block.round, self.round, block.qc.round, self.leader_elector.get_leader(block.round));
                info!("I am {}", self.name);
                ensure!(
                    block.author == self.leader_elector.get_leader(block.round),
                    ConsensusError::WrongLeader {
                        digest,
                        leader: block.author,
                        round: block.round
                    }
                );
                return Ok(());
            }
            
        }

        if (block.round == 15 || block.round == 1 ) && (nanos % 1000 == 500 || nanos % 1000 == 600|| nanos % 1000 == 700) && block.author != self.leader_elector.get_leader(block.round) {
            info!("PYTHON DETECTOR CANNOT DETECT FROM NOW!");
            info!("Attack 4 potentially detected!");
            info!("But I'm MALICIOUS NODE {} and won't tell you anything!", self.name);
            info!("Proposal's Leader {} and round {} and curr round {} and QC round {} and Original Leader {}", block.author, block.round, self.round, block.qc.round, self.leader_elector.get_leader(block.round));
            info!("PYTHON DETECTOR CAN DETECT FROM NOW!");
        }
        
        // mode 1: malicious node report correct info
        // mode 2: malicious node report no info
        // mode 3: malicious node report wrong info
        // else: honest node
        if mode == 1 && (block.round == 15 || block.round == 1 ) && (nanos % 1000 == 500 || nanos % 1000 == 600|| nanos % 1000 == 700) && block.author != self.leader_elector.get_leader(block.round) {
            info!("I'm handler {} handling for block {} with round number {} with QC {} from leader {}", self.name, block, block.round, block.qc.round, block.author);
        } else if mode == 2 && (block.round == 15 || block.round == 1 ) && (nanos % 1000 == 500 || nanos % 1000 == 600|| nanos % 1000 == 700) && block.author != self.leader_elector.get_leader(block.round) {
            info!("?");
        }else if mode == 3 && (block.round == 15 || block.round == 1 ) && (nanos % 1000 == 500 || nanos % 1000 == 600|| nanos % 1000 == 700) && block.author != self.leader_elector.get_leader(block.round) {
            info!("I'm handler {} handling for block {} with round number {} with QC {} from leader {}", self.name, block, block.round, block.round-1, block.author);
        }else {
            info!("I'm handler {} handling for block {} with round number {} with QC {} from leader {}", self.name, block, block.round, block.qc.round, block.author);
        }
        
        // Check the block is correctly formed.
        block.verify(&self.committee)?;
        // Process the QC. This may allow us to advance round.
        self.process_qc(&block.qc).await;
        // Process the TC (if any). This may also allow us to advance round.
        if let Some(ref tc) = block.tc {
            self.advance_round(tc.round).await;
        }
        // Let's see if we have the block's data. If we don't, the mempool
        // will get it and then make us resume processing this block.
        if !self.mempool_driver.verify(block.clone()).await? {
            debug!("Processing of {} suspended: missing payload", digest);
            return Ok(());
        }
        // All check pass, we can process this block.
        self.process_block(block, nanos, mode).await
    }

    async fn handle_tc(&mut self, tc: TC) -> ConsensusResult<()> {
        self.advance_round(tc.round).await;
        if self.name == self.leader_elector.get_leader(self.round) {
            self.generate_proposal(Some(tc)).await;
        }
        Ok(())
    }

    pub async fn run(&mut self) {

        
        let random = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap().subsec_nanos() % 1000;


        // Upon booting, generate the very first block (if we are the leader).
        // Also, schedule a timer in case we don't hear from the leader.
        self.timer.reset();
        if self.name == self.leader_elector.get_leader(self.round) {
            self.generate_proposal(None).await;
        }

        let mode = 3;


        // This is the main loop: it processes incoming blocks and votes,
        // and receive timeout notifications from our Timeout Manager.
        loop {
            let result = tokio::select! {
                Some(message) = self.rx_message.recv() => match message {
                    ConsensusMessage::Propose(block) => self.handle_proposal(&block, random, mode).await,
                    ConsensusMessage::Vote(vote) => self.handle_vote(&vote, random, mode).await,
                    ConsensusMessage::Timeout(timeout) => self.handle_timeout(&timeout).await,
                    ConsensusMessage::TC(tc) => self.handle_tc(tc).await,
                    _ => panic!("Unexpected protocol message")
                },
                Some(block) = self.rx_loopback.recv() => self.process_block(&block, random, mode).await,
                () = &mut self.timer => self.local_timeout_round().await,
            };
            match result {
                Ok(()) => (),
                Err(ConsensusError::StoreError(e)) => error!("{}", e),
                Err(ConsensusError::SerializationError(e)) => error!("Store corrupted. {}", e),
                Err(e) => warn!("{}", e),
            }
        }
    }
}
