import os
from pickletools import int4
import time

FILE_PATH = './logs/1_5_attack1234_1ML_RMV_same_leaders_diff_QC_for_2/2/'

proposer_list = []
proof_of_attempt_of_safety_attack = []
proof_of_attempt_of_non_safety_attack = []
voter_list = []
handler_list = []
processer_list = []

LIVENESS_OR_ACCIDENT = "This node's current action is attempting liveness attack or just is caused by timeout, ignore for this project since this project just concerns safety attack"
LIVENESS_ATTACK_TWO_PT_FOUR = "This node's is attempting liveness attack 2.4 that in current round it proposes a proposal with a round number even bigger to try overflowing"
SAFETY_ATTACK_1 = "This node is performing attack 1 that proposes multiple proposals with different QCs but same round numbers"
SAFETY_ATTACK_2_1 = "This node is performing attack 2.1 that with less round number than current round number and was not the leader for that round"
SAFETY_ATTACK_2_2 = "This node is performing attack 2.2 that with less round number than current round number and was the leader for that round but proposes a different QC"
SAFETY_ATTACK_3 = "This node is voting for proposals in attack 1"
SAFETY_ATTACK_4_1 = "This node is voting for proposals in attack 2.1"
SAFETY_ATTACK_4_2 = "This node is voting for proposals in attack 2.2"

committedRoundToQc = {}
livenessRoundToQc = {}
safetyOneRoundToQc = {}
safetyattackRound = set()

class Node():
    def __init__(self, name:str, round_number:int, qc_round_number:int):
        self.name = name
        self.round_number = round_number
        self.qc_round_number = qc_round_number

class Proposer(Node):
    def __init__(self, name, round_number, qc_round_number):
        super().__init__(name, round_number, qc_round_number)
    
    def __eq__(self, __o: object) -> bool:
        if (isinstance(__o, Proposer)):
            return self.name == __o.name and self.round_number == __o.round_number\
                and self.qc_round_number == __o.qc_round_number
        return False

class Handler(Node):
    def __init__(self, name, round_number, qc_round_number, leader=None):
        super().__init__(name, round_number, qc_round_number)
        self.leader=leader

class Processer(Node):
    def __init__(self, name, round_number, qc_round_number, leader=None):
        super().__init__(name, round_number, qc_round_number)
        self.leader=leader

class Voter(Node):
    def __init__(self, name, round_number, qc_round_number, leader=None):
        super().__init__(name, round_number, qc_round_number)
        self.leader=leader

class MaliciousNode(Node):
    def __init__(self, name, round_number, qc_round_number, attack_id, description):
        super().__init__(name, round_number, qc_round_number)
        self.attack_id = attack_id
        self.description = description
    def __eq__(self, __o: object) -> bool:
        if (isinstance(__o, MaliciousNode)):
            return self.name == __o.name and self.round_number == __o.round_number\
                and self.qc_round_number == __o.qc_round_number and self.attack_id == __o.attack_id \
                    and self.description == __o.description
        return False

class MaliciousButDueToLivenessOrAccidentNode(Node):
    def __init__(self, name, round_number, qc_round_number, description):
        super().__init__(name, round_number, qc_round_number)
        self.description = description
    def __eq__(self, __o: object) -> bool:
        if (isinstance(__o, MaliciousButDueToLivenessOrAccidentNode)):
            return self.name == __o.name and self.round_number == __o.round_number\
                and self.qc_round_number == __o.qc_round_number and self.description == __o.description
        return False

def addProposer(new_proposer):
    proposer_list.append(new_proposer)
    

# Create: positive round_number to positive qc
# Commit: negative round_number to positive qc
'''def addCreateCommitInfo(name, round_number, qc_round_number):
    if createCommittedSeq.__contains__(name):
        createCommittedSeq[name].append([round_number, qc_round_number])
    else:
        createCommittedSeq[name] = [[round_number, qc_round_number]]
'''

#https://www.tutorialspoint.com/How-to-sort-the-objects-in-a-list-in-Python#:~:text=How%20to%20sort%20the%20objects%20in%20a%20list,just%20pass%20in%20the%20reverse%20parameter%20as%20well.
def getObjKeyByRoundNumber(obj):
    return obj.round_number

def parseLog():
    node_files = [f_name for f_name in os.listdir(FILE_PATH)\
        if f_name.startswith('node')]
    for file in node_files:
        with open(FILE_PATH+file) as f:
            lines = f.readlines()
            node_name = ''
            for i in range(0, len(lines)):
                
                line_list = lines[i].split(' ')
                # print(line_list)
                # Assign node name
                if len(line_list) >= 7 and line_list[6] == 'successfully':
                    node_name = line_list[5]
                    print(node_name)
                # Record created block info, or detect liveness/accident if duplicate
                if len(line_list) >= 6 and line_list[4] == 'Created' and line_list[5] == 'with':
                    # Don't add duplicate, or add proposer and what is proposed
                    if (len(proposer_list) == 0):
                        addProposer(Proposer(node_name, int(line_list[8]), int(line_list[11])))
                        #addCreateCommitInfo(node_name, int(line_list[8]), int(line_list[11]))
                    else:
                        if (Proposer(node_name, int(line_list[8]), int(line_list[11])) != proposer_list[-1]):
                            addProposer(Proposer(node_name, int(line_list[8]), int(line_list[11])))
                            #addCreateCommitInfo(node_name, int(line_list[8]), int(line_list[11]))
                        else:
                            detectLivenessOrAccident(node_name, int(line_list[8]), int(line_list[11]), LIVENESS_OR_ACCIDENT)
                    
                # Parse Committed block Info
                if len(line_list) >= 7 and line_list[4] == 'Committed' and line_list[6] == 'with':
                    committedRoundToQc[int(line_list[5][1:])] = int(line_list[8])
                
                # Detect Attack 1
                if len(line_list) >= 7 and line_list[4] == 'Attack' and line_list[5] == '1':
                    # print(lines[i+2])
                    # Sometimes there will be "created bxx" logged before safety check log
                    locationSRO = 2
                    locationSRT = 3
                    locationAI = 4
                    if lines[i+2].split(' ')[4] == "Created":
                        locationSRO += 2
                        locationSRT += 2
                        locationAI += 2
                    checkSafetyRuleOne = lines[i+locationSRO].split(' ')[9].strip()
                    checkSafetyRuleTwo = lines[i+locationSRT].split(' ')[9].strip()
                    # Three scenarios:
                    # 1. Safety Rule 1 true and Safety Rule 2 false: Liveness
                    # 2. Safety Rule 1 false and Safety Rule 2 false: Safety Attack 1
                    # 3. Other: Liveness Or Accident
                    line_attack_info = lines[i+locationAI].split(' ')
                    if checkSafetyRuleOne == "true" and checkSafetyRuleTwo == "false":
                        detectLivenessOrAccident(line_attack_info[6].strip(), round_number=int(line_attack_info[9].strip()), \
                                qc_round_number=int(line_attack_info[17].strip()), description=LIVENESS_ATTACK_TWO_PT_FOUR)
                        
                    elif checkSafetyRuleOne == "false" and checkSafetyRuleTwo == "false" and int(line_attack_info[9].strip()) == int(line_attack_info[13].strip()):
                        detectSafetyAttack(line_attack_info[6].strip(), int(line_attack_info[9].strip()), int(line_attack_info[17].strip()),\
                                1, SAFETY_ATTACK_1)

                # Detect attack 2.1
                if len(line_list) >= 7 and line_list[4] == 'Attack' and line_list[5] == '2' \
                    and line_list[6] == 'definitely':
                    line_attack_info = lines[i+1].split(' ')
                    detectSafetyAttack(line_attack_info[6].strip(), int(line_attack_info[9].strip()), int(line_attack_info[17].strip()),\
                                2, SAFETY_ATTACK_2_1)
                # Record voter info to try detect malicious voters for attack 3 later
                if len(line_list) >= 6 and line_list[4] == "I'm" and line_list[5] == "voter":
                    voter_list.append(Voter(name=node_name, round_number=int(line_list[14].strip()), \
                        qc_round_number=int(line_list[17].strip()), leader=line_list[20].strip()))
                # Record handler info to try detect malicious voters for attack 4.1 later
                if len(line_list) >= 6 and line_list[4] == "I'm" and line_list[5] == "handler":
                    handler_list.append(Handler(name=node_name, round_number=int(line_list[14].strip()), \
                        qc_round_number=int(line_list[17].strip()), leader=line_list[20].strip()))
                # Record processor info to try detect malicious voters for attack 4.2 later
                if len(line_list) >= 6 and line_list[4] == "I'm" and line_list[5] == "processor":
                    processer_list.append(Processer(name=node_name, round_number=int(line_list[14].strip()), \
                        qc_round_number=int(line_list[17].strip()), leader=line_list[20].strip()))
                    

    # sort proposer by round number
    proposer_list.sort(key=getObjKeyByRoundNumber)
    proof_of_attempt_of_safety_attack.sort(key=getObjKeyByRoundNumber)
    proof_of_attempt_of_non_safety_attack.sort(key=getObjKeyByRoundNumber)
    
    # https://www.techiedelight.com/sort-list-of-objects-by-multiple-attributes-python/#:~:text=A%20Pythonic%20solution%20to%20in-place%20sort%20a%20list,key%20and%20reverse%20and%20produces%20a%20stable%20sort.
    voter_list.sort(key=lambda x: (x.name, x.round_number))
    handler_list.sort(key=lambda x: (x.name, x.round_number))

    # Remove duplicate 
    if len(proof_of_attempt_of_safety_attack) != 0:
        remove_duplicate_safety_attack()
    if len(proof_of_attempt_of_non_safety_attack) != 0:
        remove_duplicate_liveness_attack()
    for proposer in proposer_list:
        print(proposer.name, proposer.round_number, proposer.qc_round_number)
    print(committedRoundToQc)

# Util for adding safety attack proof for one malicious node
def detectSafetyAttack(name, round_number, qc_round_number, attack_id, description):
    proof_of_attempt_of_safety_attack.append(MaliciousNode(name=name,\
                                round_number=round_number, qc_round_number=qc_round_number, \
                                    attack_id=attack_id, description=description))

# Util for removing dup
def remove_duplicate_safety_attack():
    print("DEDUP")
    
    deduplicated_proof_of_attempt_of_safety_attack = [proof_of_attempt_of_safety_attack[0]]
    for i in range(1, len(proof_of_attempt_of_safety_attack)):
        if proof_of_attempt_of_safety_attack[i] != proof_of_attempt_of_safety_attack[i-1]:
            deduplicated_proof_of_attempt_of_safety_attack.append(proof_of_attempt_of_safety_attack[i])
    proof_of_attempt_of_safety_attack.clear()
    for i in deduplicated_proof_of_attempt_of_safety_attack:
        safetyattackRound.add(i.round_number)
        proof_of_attempt_of_safety_attack.append(i)

# Util for removing dup
def remove_duplicate_liveness_attack():
    print("DEDUP")
    deduplicated_proof_of_attempt_of_non_safety_attack = [proof_of_attempt_of_non_safety_attack[0]]
    for i in range(1, len(proof_of_attempt_of_non_safety_attack)):
        if proof_of_attempt_of_non_safety_attack[i] != proof_of_attempt_of_non_safety_attack[i-1]:
            deduplicated_proof_of_attempt_of_non_safety_attack.append(proof_of_attempt_of_non_safety_attack[i])
    proof_of_attempt_of_non_safety_attack.clear()
    for i in deduplicated_proof_of_attempt_of_non_safety_attack:
        proof_of_attempt_of_non_safety_attack.append(i)

# Detect Attack 1: One leader proposes proposals with different QCs but same round numbers within 1 round
# Also detect Attack 2.1: 
# One leader proposes proposals with non-consecutive round number R
# Suppose current round number CR,
# Current leader is L
# Leader in R was PL
# If R < CR, L ! PL
# Then Attack 2.1
# Also detect Attack 2.2: 
# One leader proposes proposals with non-consecutive round number R
# Suppose current round number CR,
# Current leader is L
# Leader in R was PL
# L's proposal's QC in CR is QC
# RL's proposal was PQC
# If R < CR, L = PL, and QC != PQC
# Then Attack 2.2
    

# Just put liveness or accidental stuff inside 
def detectLivenessOrAccident(name, round_number, qc_round_number, description):
    proof_of_attempt_of_non_safety_attack.append(MaliciousButDueToLivenessOrAccidentNode(name, round_number, qc_round_number, description ))

# Detect attack 2.2
def detectAttackTwoPtTwo():
    for i in range(1,len(proposer_list)):
        if proposer_list[i].name == proposer_list[i-1].name and \
            proposer_list[i].round_number == proposer_list[i-1].round_number and \
            proposer_list[i].round_number not in safetyattackRound:
            detectSafetyAttack(proposer_list[i].name, proposer_list[i].round_number, \
                proposer_list[i].qc_round_number, 2, SAFETY_ATTACK_2_2)

def initDetector():
    detectAttackTwoPtTwo()

# Detect attack 3
def detectAttackThree():
    if len(proof_of_attempt_of_safety_attack) == 0:
        return
    attack_one_list = []
    # Gather all leaders doing attack 1
    for attack in proof_of_attempt_of_safety_attack:
        if attack.attack_id == 1:
            attack_one_list.append(attack)
            print(attack.name,attack.round_number, attack.qc_round_number, attack.description )
    for attack in attack_one_list:
        for voter in voter_list:
            if voter.round_number == attack.round_number and \
                voter.qc_round_number == attack.qc_round_number and\
                voter.leader == attack.name and\
                    proof_of_attempt_of_safety_attack[-1] != MaliciousNode(name=voter.name, round_number=voter.round_number,\
                    qc_round_number=voter.qc_round_number, attack_id=3, description=SAFETY_ATTACK_3):
                detectSafetyAttack(name=voter.name, round_number=voter.round_number,\
                    qc_round_number=voter.qc_round_number, attack_id=3, description=SAFETY_ATTACK_3)
                print(voter.name, voter.round_number, voter.qc_round_number)

# Detect attack 4
def detectAttackFour():
    attack_two_pt_one_list = []
    # Gather all leaders doing attack 2.1
    for attack in proof_of_attempt_of_safety_attack:
        if attack.description == SAFETY_ATTACK_2_1:
            attack_two_pt_one_list.append(attack)
            print(attack.name,attack.round_number, attack.qc_round_number, attack.description )
    for attack in attack_two_pt_one_list:
        for handler in handler_list:
            # need to check leader too to avoid false positive like the 1 0, 1 0 examples
            if handler.round_number == attack.round_number and \
                handler.qc_round_number == attack.qc_round_number and \
                handler.leader == attack.name and\
                    proof_of_attempt_of_safety_attack[-1] != MaliciousNode(name=handler.name, round_number=handler.round_number,\
                    qc_round_number=handler.qc_round_number, attack_id=4, description=SAFETY_ATTACK_4_1):
                detectSafetyAttack(name=handler.name, round_number=handler.round_number,\
                    qc_round_number=handler.qc_round_number, attack_id=4, description=SAFETY_ATTACK_4_1)

    attack_two_pt_two_list = []
    # Gather all leaders doing attack 2.2
    for attack in proof_of_attempt_of_safety_attack:
        if attack.description == SAFETY_ATTACK_2_2:
            attack_two_pt_two_list.append(attack)
            print(attack.name,attack.round_number, attack.qc_round_number, attack.description )
    for attack in attack_two_pt_two_list:
        for processer in processer_list:
            # need to check leader too to avoid false positive like the 1 0, 1 0 examples
            if processer.round_number == attack.round_number and \
                processer.qc_round_number == attack.qc_round_number and \
                processer.leader == attack.name and\
                    proof_of_attempt_of_safety_attack[-1] != MaliciousNode(name=processer.name, round_number=processer.round_number,\
                    qc_round_number=processer.qc_round_number, attack_id=4, description=SAFETY_ATTACK_4_2):
                detectSafetyAttack(name=processer.name, round_number=processer.round_number,\
                    qc_round_number=processer.qc_round_number, attack_id=4, description=SAFETY_ATTACK_4_2)
                print(processer.name, processer.round_number, processer.qc_round_number)

def main():
    start_time = time.time()
    parseLog()
    initDetector()
    '''for i in voter_list:
        print("voter", i.name, i.round_number, i.qc_round_number)
    for i in handler_list:
        print("handler", i.name, i.round_number, i.qc_round_number)'''
    detectAttackThree()
    detectAttackFour()
    print("\n\nFinal Safety Attack")
    for i in proof_of_attempt_of_safety_attack:
        print(i.name, i.round_number, i.qc_round_number, i.description)
    elapsed_time = time.time() - start_time
    print("Time to detect malicious nodes: ", elapsed_time, "seconds")

if __name__=='__main__':
    main()