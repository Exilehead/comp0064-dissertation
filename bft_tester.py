# Not using pytest since correctness is what this project seeks for
# instead of strictly 100% passing all test cases
from doctest import testfile
from re import I
from bft_detector import run
import os
import sys

STDIN_FOLDER = 'logs/1_10_1ML/'
MALICIOUS_RANDOM_NODE_ID = [500, 600, 700]
MALICIOUS_LEADER_ROUND_OF_ATTACK = {10: 0, 15: 0}
file_index_to_malicious_nodes = {}
file_index_to_malicious_nodes_cheated = {}
file_index_to_all_lines = {}
TIME_LIMIT = 60
time = []
pubkey_to_attack_id = {}
pubkey_to_attack_id_cheated = {}

# This is a basic test
# test if detector work well without compilation error
# and can stdout the files of detection results
def test_stdout_files(file, fn):
    run(file, fn)
    return

# This is a basic test
# test if honest nodes are wrongly caught as malicious(false positive)
# return false positive nodes and Precision (SupposesMaliciousNodes/(WronglyCaughtHonestNodes+SupposesMaliciousNodes))
def test_all_detected_precision():
    print("\n\n-----------False Positive Test Start--------------\n\n")
    SupposesMaliciousNodes = 0
    WronglyCaughtHonestNodes = 0
    for k, _ in file_index_to_malicious_nodes.items():
        if len(file_index_to_malicious_nodes[k]) == len(file_index_to_malicious_nodes_cheated[k]):
            print("\nMatches numbers of unique malicious nodes")
            print("Detector's malicious nodes:", file_index_to_malicious_nodes[k], \
                "with numbers of ", len(file_index_to_malicious_nodes[k]))
            print("Actual malicious nodes:", file_index_to_malicious_nodes_cheated[k], \
                "with numbers of ", len(file_index_to_malicious_nodes_cheated[k]), "\n")
        elif len(file_index_to_malicious_nodes[k]) > len(file_index_to_malicious_nodes_cheated[k]):
            print("\nNOT Matches numbers of unique malicious nodes")
            print("Detector's malicious nodes:", file_index_to_malicious_nodes[k], \
                "with numbers of ", len(file_index_to_malicious_nodes[k]))
            print("Actual malicious nodes:", file_index_to_malicious_nodes_cheated[k], \
                "with numbers of ", len(file_index_to_malicious_nodes_cheated[k]), "\n")
            WronglyCaughtHonestNodes += len(file_index_to_malicious_nodes[k]) - len(file_index_to_malicious_nodes_cheated[k])
        SupposesMaliciousNodes += len(file_index_to_malicious_nodes_cheated[k])
    precision = SupposesMaliciousNodes/(WronglyCaughtHonestNodes+SupposesMaliciousNodes)
    print("\n\n-----------Precision is", "{:.2%}".format(precision), "--------------\n\n")
    print("\n\n-----------False Positive Test End--------------\n\n")
    return precision
# This is a basic test
# test if malicious nodes are not detected
# return false negative nodes and Recall (SupposesMaliciousNodes/(IgnoredMaliciousNodes+SupposesMaliciousNodes))
def test_all_detected_recall():
    print("\n\n-----------False Negative Test Start--------------\n\n")
    SupposesMaliciousNodes = 0
    IgnoredMaliciousNodes = 0
    for k, _ in file_index_to_malicious_nodes.items():
        if len(file_index_to_malicious_nodes[k]) == len(file_index_to_malicious_nodes_cheated[k]):
            print("\nMatches numbers of unique malicious nodes")
            print("Detector's malicious nodes:", file_index_to_malicious_nodes[k], \
                "with numbers of ", len(file_index_to_malicious_nodes[k]))
            print("Actual malicious nodes:", file_index_to_malicious_nodes_cheated[k], \
                "with numbers of ", len(file_index_to_malicious_nodes_cheated[k]), "\n")
        elif len(file_index_to_malicious_nodes[k]) < len(file_index_to_malicious_nodes_cheated[k]):
            print("\nNOT Matches numbers of unique malicious nodes")
            print("Detector's malicious nodes:", file_index_to_malicious_nodes[k], \
                "with numbers of ", len(file_index_to_malicious_nodes[k]))
            print("Actual malicious nodes:", file_index_to_malicious_nodes_cheated[k], \
                "with numbers of ", len(file_index_to_malicious_nodes_cheated[k]), "\n")
            IgnoredMaliciousNodes += len(file_index_to_malicious_nodes_cheated[k]) - len(file_index_to_malicious_nodes[k])
        SupposesMaliciousNodes += len(file_index_to_malicious_nodes_cheated[k])
    recall = SupposesMaliciousNodes/(IgnoredMaliciousNodes+SupposesMaliciousNodes)
    print("\n\n-----------Recall is", "{:.2%}".format(recall), "--------------\n\n")
    print("\n\n-----------False Negative Test End--------------\n\n")
    return recall

# This is a basic test
# test is time in quasi-real time
def test_time():
    print("\n\n-----------Time Test Start--------------\n\n")
    for tm in time:
        if tm > TIME_LIMIT:
            print("\n\n-----------Time Test End--------------\n\n")
            return False
    print("\n\n-----------Time Test End--------------\n\n")
    return True

def gather_attack_category_by_attack_id():
    for k, v in file_index_to_malicious_nodes.items():
        for pubkey in v:
            for k_2, v_2 in file_index_to_all_lines.items():
                for line in v_2:
                    if line[1].strip() == pubkey and (line[0].strip() == '3' or line[0].strip() == '4'):
                        if pubkey_to_attack_id.get(pubkey, "default") == "default":
                            pubkey_to_attack_id[pubkey] = [int(line[0].strip())]
                        else:
                            pubkey_to_attack_id[pubkey].append(int(line[0].strip()))
    for k, v in pubkey_to_attack_id.items():
        pubkey_to_attack_id[k].sort()
    print(pubkey_to_attack_id)

def gather_attack_category_by_cheating():
    for k,v in pubkey_to_attack_id_cheated.items():
        pubkey_to_attack_id_cheated[k] = list(set(v))
    print(pubkey_to_attack_id_cheated)

# This is an advanced test
# test is each attack really belongs to its attack category, focusing on voter
# eg: the proof "3 Dn2i9Ipd91uJqz0C 10 0 This node is performing attack 3.1 that it votes for proposals in attack 1, and it is reporting CORRECT voting information"
# Test is the above pubkey Dn2i9Ipd91uJqz0C really performing Attack 3
# return correctness
def test_attack_category_voter():
    print("\n\n-----------Verify Voter does do its attack 3 or 4 Test Start--------------\n\n")
    gather_attack_category_by_attack_id()
    gather_attack_category_by_cheating()
    DetectorCorrectNumber = 0
    ActualCorrectNumber = 0
    # for cheat_list and detector_list there will only be [3, 4] or [4], or [3] or no key
    for k,cheat_list in pubkey_to_attack_id_cheated.items():
        ActualCorrectNumber += len(cheat_list)
        detector_list = []
        try:
            detector_list = pubkey_to_attack_id[k]
        except:
            # If no key then wrong and continue
            continue
        # If length not same, then will either [3] vs [3,4] or [4] vs [3,4], One fault
        if len(cheat_list) != len(detector_list):
            print("Mismatch: cheat_list is", cheat_list, "from pubkey", k, "and detector_list is",detector_list )
            DetectorCorrectNumber += 1
            continue
        # Now length same and is 1 for both. If content not same, like [3] vs [4], One fault
        if cheat_list[0] != detector_list[0]:
            print("Mismatch: cheat_list is", cheat_list, "from pubkey", k, "and detector_list is",detector_list )
            continue
        # Below is matching and add the deserved number
        if len(cheat_list) == 1:
            DetectorCorrectNumber += 1
            continue
        if len(cheat_list) == 2:
            DetectorCorrectNumber += 2
            continue
    correctness = DetectorCorrectNumber/ActualCorrectNumber
    print("\n\n-----------Correctness is ", correctness, "--------------\n\n")
    print("\n\n-----------Verify Voter does do its attack 3 or 4 Test End--------------\n\n")
    return correctness


def gather_results_from_detection():
    # Gather test file index mapped to malicious nodes and all results of detection 
    for i in range(1, 21): 
        with open('tests/test' + str(i) + '.txt') as f:
            lines = f.readlines()
            
            for line_index in range(0, len(lines)):
                line = lines[line_index].split(' ')
                print(line)
                if line[0] != "Final" and line[0] != "Time":
                    if file_index_to_all_lines.get(i, "default") == "default":
                        file_index_to_all_lines[i] = [line]
                    else:
                        file_index_to_all_lines[i].append(line)
                    if file_index_to_malicious_nodes.get(i, "default") == "default":
                        file_index_to_malicious_nodes[i] = [line[1]]
                    else:
                        file_index_to_malicious_nodes[i].append(line[1])
                if line[0] == "Time":
                    time.append(float(line[6].strip()))
        if file_index_to_malicious_nodes.get(i, "default") == "default":
            file_index_to_malicious_nodes[i] = []
        else:
            file_index_to_malicious_nodes[i] = list(set(file_index_to_malicious_nodes[i]))

    print(file_index_to_malicious_nodes)

def gather_results_from_files_by_cheating():
    # Gather additional logs that should not be interpreted by the detector
    # due to the instinct that they are for testing
    for i in range(1, 21):
        file_path = STDIN_FOLDER + str(i) + '/'
        node_files = [f_name for f_name in os.listdir(file_path)\
        if f_name.startswith('node')]
        for file in node_files:
            with open(file_path+file) as f:
                lines = f.readlines()
                node_name = ''
                for index in range(0, len(lines)):
                    line_list = lines[index].split(' ')
                    if len(line_list) >= 7 and line_list[6] == 'successfully':
                        node_name = line_list[5]
                    # Get all malicious leaders:
                    if len(line_list) >= 12 and line_list[4] == 'Created' and line_list[5] == 'with':
                        for k,v in MALICIOUS_LEADER_ROUND_OF_ATTACK.items():
                            if k == int(line_list[8].strip()) and v == int(line_list[11].strip()):
                                if file_index_to_malicious_nodes_cheated.get(i, "default") == "default":
                                    file_index_to_malicious_nodes_cheated[i] = [node_name]
                                else:
                                    file_index_to_malicious_nodes_cheated[i].append(node_name)
                    # Get all malicious voters
                    if len(line_list) >= 11 and line_list[9] == 'nanos':
                        random = int(line_list[10].strip())
                        #print(random)
                        if random in MALICIOUS_RANDOM_NODE_ID:
                            if file_index_to_malicious_nodes_cheated.get(i, "default") == "default":
                                file_index_to_malicious_nodes_cheated[i] = [node_name]
                            else:
                                file_index_to_malicious_nodes_cheated[i].append(node_name)

                    if len(line_list) >= 7 and line_list[4] == 'Attack' and line_list[5] == '3':
                        if pubkey_to_attack_id_cheated.get(node_name, "default") == "default":
                            pubkey_to_attack_id_cheated[node_name] = [3]
                        else:
                            pubkey_to_attack_id_cheated[node_name].append(3)

                    if len(line_list) >= 7 and line_list[4] == 'Attack' and line_list[5] == '4':
                        if pubkey_to_attack_id_cheated.get(node_name, "default") == "default":
                            pubkey_to_attack_id_cheated[node_name] = [4]
                        else:
                            pubkey_to_attack_id_cheated[node_name].append(4)

        if file_index_to_malicious_nodes_cheated.get(i, "default") == "default":
            file_index_to_malicious_nodes_cheated[i] = []
        else:
            file_index_to_malicious_nodes_cheated[i] = list(set(file_index_to_malicious_nodes_cheated[i]))
    print(file_index_to_malicious_nodes_cheated)

def main():
    temp = sys.stdout
    for i in range(1, 21):
        test_stdout_files(STDIN_FOLDER+str(i)+'/', i)
    sys.stdout = temp
    gather_results_from_detection()
    gather_results_from_files_by_cheating()
    precision = test_all_detected_precision()
    recall = test_all_detected_recall()
    is_exceed_time_limit = test_time()
    
    correctness_voter = test_attack_category_voter()
    print("\n\n\n---------------------------BASIC TEST DONE---------------------------------------")
    print("\n\n\n---------------------------PRECISION IS ","{:.2%}".format(precision), "---------------------------------------")
    print("\n\n\n---------------------------RECALL IS ","{:.2%}".format(recall), "---------------------------------------")
    print("\n\n\n---------------------------IS RUN IN QUASI-REAL TIME?",is_exceed_time_limit,"---------------------------------------\n\n\n")
    print("\n\n\n---------------------------ADVANCED TEST DONE---------------------------------------")
    print("\n\n\n-------------------CORRECTNESS THAT MALICOUS VOTER'S ATTACK CATEGORY IS CORRECTLY IDENTIFIED IS ","{:.2%}".format(correctness_voter), "---------------------------------")
if __name__=='__main__':
    main()