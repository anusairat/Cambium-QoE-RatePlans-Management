
#!/usr/pkg/bin/python

import json
import requests
import os
import sys
import argparse
from optparse import OptionParser
import csv



## Supress HTTPS Insecure Request warning
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

######################################################################
################                                        ##############
################                To Do                   ##############
################                                        ##############
######################################################################
# To Do: Change to match your configuration
QoE_MNG_IP = "10.0.0.100"
QoE_REST_PORT = "3443"
QoE_REST_USER = "qoe-rest-user"
QoE_REST_PASSWORD = "qoe-rest-passwd"


######################################################################
################                                        ##############
################                Do Not Change           ##############
################                                        ##############
######################################################################
## Do not change
REST_API_END_POINT = "/api/v1/"
URL_PREFIX = "https://" + QoE_MNG_IP + ":" + QoE_REST_PORT + REST_API_END_POINT


######################################################################
################                                        ##############
################     Functiosn Supporting REST APIs     ##############
################                                        ##############
######################################################################

def print_stderr(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def print_qoe_access_info():
    print_stderr("QoE IP Address:       {:s}".format(QoE_MNG_IP))
    print_stderr("QoE Port:             {:s}".format(QoE_REST_PORT))
    print_stderr("QoE REST User:        {:s}".format(QoE_REST_USER))
    print_stderr("QoE REST Password:    {:s}".format(QoE_REST_PASSWORD))
    

def does_file_exist(fileName):

    if os.path.isfile(fileName) and os.access(fileName, os.R_OK):
        return True
    else:
        return False


def read_qoe_rest_access_info(configFileName):
    global QoE_MNG_IP, QoE_REST_PORT, QoE_REST_USER, QoE_REST_PASSWORD, URL_PREFIX

    if configFileName is None:
        print_stderr("using default QoE REST access info")
        print_qoe_access_info()
        return
    
    if does_file_exist(configFileName):
        # Open the file in read mode
        with open(configFileName, 'r') as file:
            # Read all lines and store them in a list
            lines = file.readlines()

        if len(lines) < 4:
            print_stderr("{:s} file must have at least 4 lines: \nQoE Managment IP \nREST API Port \nREST API User Name \nREST API Password".format(configFileName))
            exit()
        
        QoE_MNG_IP = lines[0].strip()
        QoE_REST_PORT = lines[1].strip()
        QoE_REST_USER = lines[2].strip()
        QoE_REST_PASSWORD = lines[3].strip()

        if QoE_MNG_IP == "" or QoE_REST_PORT == "" or QoE_REST_USER =="" or QoE_REST_PASSWORD == "":
            print_stderr("{:s} file must have at least 4 lines: \nQoE Managment IP \nREST API Port \nREST API User Name \nREST API Password".format(configFileName))
            exit()

        URL_PREFIX = "https://" + QoE_MNG_IP + ":" + QoE_REST_PORT + REST_API_END_POINT

        print_qoe_access_info()
    else:
        print_stderr("using default QoE REST access info")
        print_qoe_access_info()

    


def processResponse(response, print_resp=1):
    if(print_resp == 1):
        if("Content-Length" in response.headers and int(response.headers["Content-Length"]) > 0):
            print(json.dumps(response.json(), indent=4))
    return response.status_code

def standarizePolicyName(policyName):
    policyName = policyName.replace(' ', '-')
    policyName = policyName.replace('/', '_')
    policyName = policyName.replace('\\', '_')

    return policyName


def addPolicy(policyName, downlinkRate, uplinkRate, policyId, acm):
    #### Add new Policy

    policyName = standarizePolicyName(policyName)

    downlinkRate = int(downlinkRate) # remove fraction from rate
    uplinkRate = int(uplinkRate) # remove fraction from rate

    #### Add new Policy
    print_stderr(f"Adding new Policy ==>  Name: [{policyName}], Id: [{policyId}], DL Rate(kbps): [{downlinkRate}], UL Rate (kbps): [{uplinkRate}],  ACM: {acm}")
    headers = {
        # Already added when you pass json= but not when you pass data=
        # 'Content-Type': 'application/json',
    }

    json_data = {
        'policyId': policyId,
    }

    if(downlinkRate > 0):
        json_data['rateLimitDownlink'] = {
            'rate': int(downlinkRate),
            'congestionMgmt': acm,
        }
    else:
        json_data['rateLimitDownlink'] = {
            'congestionMgmt': acm,
        }

    if(uplinkRate > 0):
        json_data['rateLimitUplink'] = {
            'rate': int(uplinkRate),
        }


    response = requests.post(URL_PREFIX + 'policies/rate/' + policyName, headers=headers, json=json_data, verify=False, auth=(QoE_REST_USER, QoE_REST_PASSWORD))
    if(processResponse(response) >= 400):
        #print_stderr ("Error adding subscriber rate policy\n")
        return -1

    return 0


def retrievPolicy(policyName):
    ### Retrieve Policies
    POLICY_PREFIX = 'policies/rate'
    if(policyName == ""):
        print_stderr("Retrieving All Policies")
    else:
        POLICY_PREFIX = POLICY_PREFIX + "/"
        print_stderr("Retrieving Policy: ", policyName)

    headers = {
        'Content-Type': 'application/json',
    }
    response = requests.get(URL_PREFIX + POLICY_PREFIX + policyName, headers=headers, verify=False, auth=(QoE_REST_USER, QoE_REST_PASSWORD))

    if(processResponse(response) >= 400):
        #print_stderr ("Error retrieving rate policy details\n")
        return -1
    else:
        return 0


def deletePolicyByName(policyName):
    #### Delete a policy:
    headers = {
        'Content-Type': 'application/json',
    }
    print_stderr("Deleting Policy: ", policyName)
    response = requests.delete(URL_PREFIX + 'policies/rate/' + policyName, headers=headers, verify=False, auth=(QoE_REST_USER, QoE_REST_PASSWORD))
    if(processResponse(response) >= 400):
        #print("Error deleting policy\n")
        return -1
    return 0

def deletePolicyById(policyId):
    #### Delete a policy:
    headers = {
        'Content-Type': 'application/json',
    }
    params = {
        'policyId': policyId,
    }

    print_stderr("Deleting Policies with Id: ", policyId)
    response = requests.delete(URL_PREFIX + 'policies/rate/', params=params, headers=headers, verify=False, auth=(QoE_REST_USER, QoE_REST_PASSWORD))
    if(processResponse(response) >= 400):
        #print_stderr("Error deleting policies with Id  %s\n" %policyId)
        return -1
    return 0


def assignSubscriberToRatePolicy(subscriber, subscriberId, policyName, qoutaEnabled=False, qouta_details=None):
    #### Assign Subscriber to a policy
    print_stderr('Adding policy {:s} for subscriber {:s}'.format(policyName, subscriber))
    headers = {
        # Already added when you pass json=
        # 'Content-Type': 'application/json',
    }
    
    
    json_data = {
        'policyRate': policyName,
        'subscriberId': subscriberId,
    }

    quota_dict = {}
    if qoutaEnabled:
        if(qouta_details[0] > 0):
            quota_dict['time'] = qouta_details[0]
        if(qouta_details[2] > 0 ): # if volume is present it overwites volumeIncrement, so check volumeIncrement first, if it is > 0 then ignore the volume field.
                                    # user is trying to increase the qouta by the volumeIncrement value.
            quota_dict['volumeIncrement'] = qouta_details[2]
        elif(qouta_details[1] > 0):
            quota_dict['volume'] = qouta_details[1]
        
        json_data['quota'] = quota_dict
    
    if(retrieveSubscriberRatePolicy(subscriber, 0) == -1):  # subscriber does not exist .. use POST method
        response = requests.post(URL_PREFIX + 'subscribers/' + subscriber, headers=headers, json=json_data, verify=False, auth=(QoE_REST_USER, QoE_REST_PASSWORD))
    else:  # subscriber exists .. use PUT method
        response = requests.put(URL_PREFIX + 'subscribers/' + subscriber, headers=headers, json=json_data, verify=False, auth=(QoE_REST_USER, QoE_REST_PASSWORD))

    if(processResponse(response) >= 400):
        #print_stderr("Error assiging Policy to the subscriber\n")
        # json_resp = response.json()
        # print_stderr("Response Code ==> " + str(json_resp["error"]["code"]))
        # print_stderr("Response subCode ==> " + str(json_resp["error"]["subCode"]))
        # print_stderr("Response message ==> " + str(json_resp["error"]["message"]))
        return -1

    return 0


def retrieveSubscriberRatePolicy(subscriber, print_resp = 1):

    #### Show subscriber(s) (with the associated policy)
    SUBSCRIBER_PREFIX = 'subscribers'

    if(subscriber == ""):
        print_stderr("Retrieving All subscribers policies")
    else:
        SUBSCRIBER_PREFIX = SUBSCRIBER_PREFIX + "/"
        print_stderr("Retrieving Subscriber {:s} Policy: ".format(subscriber))

    headers = {
        'Content-Type': 'application/json',
    }

    response = requests.get(URL_PREFIX + SUBSCRIBER_PREFIX + subscriber, headers=headers, verify=False, auth=(QoE_REST_USER, QoE_REST_PASSWORD))
    if(processResponse(response, print_resp) >= 400):
        print_stderr("Error retrieving subscriber rate policy\n")
        return -1

    return 0



def deleteSubscriberRatePolicy(subscriber):
    ##### Delete the assignment of a subscriber to a policy:
    headers = {
        'Content-Type': 'application/json',
    }
    print_stderr('Deleting policy for subscriber {:s}'.format(subscriber))
    response = requests.delete(URL_PREFIX + 'subscribers/' + subscriber, headers=headers, verify=False, auth=(QoE_REST_USER, QoE_REST_PASSWORD))
    if(processResponse(response) >= 400):
        #print_stderr("Error deleting subscriber rate policy\n")
        return -1

    return 0

def deleteSubscriberRatePolicyBySubID(subscriberId):
    ##### Delete the assignment of a subscriber to a policy:

    headers = {
        'Content-Type': 'application/json',
    }

    params = {
        'subscriberId': subscriberId,
    }

    print_stderr('Deleting policy for subscriberId {:s}'.format(subscriberId))
    response = requests.delete(URL_PREFIX + 'subscribers', headers=headers, params=params, verify=False, auth=(QoE_REST_USER, QoE_REST_PASSWORD))
    if(processResponse(response) >= 400):
        #print_stderr("Error deleting subscriber rate policy\n")
        return -1

    return 0

def retrievSubscriberMetrics(subscriber, metric, interval, period):
    #### Get the metrics of one subscriber (in this case, the bandwidth for the last five hours):
    print_stderr('Retrieving subscriber {:s} metrics'.format(subscriber))

    headers = {
        'Content-Type': 'application/json',
    }

    params = {
        'interval': interval,
        'period': period,
    }

    response = requests.get(URL_PREFIX + 'subscribers/' + subscriber +'/' + metric, params=params, headers=headers, verify=False, auth=(QoE_REST_USER, QoE_REST_PASSWORD))
    if(processResponse(response) >= 400):
        #print_stderr("Error retrieving subscriber metrics\n")
        return -1

    return 0



######################################################################
################                                        ##############
################    General Functions                   ##############
################                                        ##############
######################################################################



######################################################################
################                                        ##############
################        CLI based Functions()           ##############
################                                        ##############
######################################################################

######################################
##### Adding Policy
######################################

def displayAddPolicyUsage():
    print_stderr("\nUsage:")
    print_stderr(os.path.basename(__file__) + " addPolicy --policyName [policyname] --policyId [policyId] --downlinkRate [dlRate_kbps] --uplinkRate [ulRate_kbps] --acm [true/false]")
    print_stderr("")

def addPolicyFromCLI(args):
    print_stderr("Adding Policy through CLI")
    #print_stderr(args)
    if args.policyName is None:
        print_stderr("Missing policyName")
        displayAddPolicyUsage()
        return -1

    if args.policyId is None:
        print_stderr("Missing policyId")
        displayAddPolicyUsage()
        return -1

    if args.downlinkRate is None:
        args.downlinkRate = -1

    if args.uplinkRate is None:
        args.uplinkRate = -1


    acm = True
    if args.acm is not None:
        if args.acm.lower() == "false":
            acm = False


    return addPolicy(args.policyName, args.downlinkRate, args.uplinkRate, args.policyId, acm)


######################################
##### Retrieving Policy
######################################

def getPolicyFromCLI(args):
    print_stderr("Get Policy through CLI")
    if args.policyName is None:
        return retrievPolicy("")
    else:
        return retrievPolicy(args.policyName)

######################################
##### Delete Policy
######################################

def displaydeletePolicyUsage():
    print_stderr("\nUsage:")
    print_stderr(os.path.basename(__file__) + " deletePolicy --policyName [policyname] OR --policyId [policyId]")
    print_stderr("")

def deletePolicyFromCLI(args):
    print_stderr("Delete Policy through CLI")
    if args.policyName is not None:
        return deletePolicyByName(args.policyName)
    elif args.policyId is not None:
        return deletePolicyById(args.policyId)
    else:
        print_stderr("Missing PolicyName or PolicyId")
        displaydeletePolicyUsage()
        return -1


######################################
##### Retrieving Subscriber's Policy
######################################
def displaySetSubRatePolicyUsage():
    print_stderr("\nUsage:")
    print_stderr(os.path.basename(__file__) + " setSubRatePolicy --subscriber [IPv4] --subscriberId [ID] --policyName [policyname]")
    print_stderr("")

def setSubRatePolicyFromCLI(args):
    print_stderr("Assigning Subscriber to Policy through CLI")
    #print_stderr(args)
    if args.policyName is None:
        print_stderr("Missing policyName")
        displaySetSubRatePolicyUsage()
        return -1
    elif args.subscriber is None:
        print_stderr("Missing subscriber")
        displaySetSubRatePolicyUsage()
        return -1

    if args.subscriberId is None:
        args.subscriberId = ""

    noQouta = []
    policyName = standarizePolicyName(args.policyName)
    return assignSubscriberToRatePolicy(args.subscriber, args.subscriberId, policyName, 0, noQouta)

######################################
##### Retrieving Subscriber's Policy
######################################
def displaygetSubRatePolicyUsage():
    print_stderr("\nUsage:")
    print_stderr(os.path.basename(__file__) + " getSubRatePolicy --subscriber [IPv4] ")
    print_stderr("")

def getSubRatePolicyFromCLI(args):
    #print_stderr("Retrieving Subscriber's Policy through CLI")
    #print_stderr(args)
    if args.subscriber is None:
        return retrieveSubscriberRatePolicy("")
    else:
        return retrieveSubscriberRatePolicy(args.subscriber)

######################################
##### Delete Subscriber's Policy
######################################
def displayDeleteSubRatePolicyUsage():
    print_stderr("\nUsage:")
    print_stderr(os.path.basename(__file__) + " deleteSubRatePolicy --subscriber [IPv4] | --subscriberId [ID]")
    print_stderr("")

def deleteSubRatePolicyFromCLI(args):
    print_stderr("Deleting Subscriber's Policy through CLI")
    #print_stderr(args)
    if args.subscriber is not None:
        return deleteSubscriberRatePolicy(args.subscriber)
    elif args.subscriberId is not None:
        return deleteSubscriberRatePolicyBySubID(args.subscriberId)
    else:
        print_stderr("Missing subscriber")
        displayDeleteSubRatePolicyUsage()
        return -1




######################################
##### Retrieving Subscriber's Stats
######################################

def displaygetSubMetricsUsage():
    print_stderr("\nUsage:")
    print_stderr(os.path.basename(__file__) + " getSubMetrics --subscriber [IPv4] --metric [bandwidth|flows|latency|retransmission|volume] --metric_interval [interval-minutes] --metric_period [period-hours]")
    print_stderr("")

def getSubMetricsFromCLI(args):

    print_stderr("Getting subscriber metrics through CLI")
    #print_stderr(args)
    if args.subscriber is None:
        print_stderr("Missing subscriber")
        displaygetSubMetricsUsage()
        return -1
    elif args.metric is None:
        print_stderr("Missing metric type")
        displaygetSubMetricsUsage()
        return -1

    args.metric = args.metric.lower()

    if args.metric not in ["bandwidth","flows", "latency", "retransmission", "volume"]:
        print_stderr("Unknown metric type")
        displaygetSubMetricsUsage()
        return -1

    if args.metric_interval is None:
        args.metric_interval = 60

    if args.metric_period is None:
        args.metric_period = 24

    return retrievSubscriberMetrics(args.subscriber, args.metric, args.metric_interval, args.metric_period)




######################################
##### Configure Sub Rate Plans From File
######################################

def read_subs_plans(subsFile):

    with open(subsFile, 'r') as csvfile:
        csvreader = csv.reader(csvfile, delimiter=',')
        header = next(csvreader)
        rows = []
        for row in csvreader:
            rows.append(row)
        return rows


def find_all_rate_plans(subsRates):

    ratePlans = []
    tempRatePlans = []
    ratesIndex = 0
    subsRatePlansIndices = []
    if len(subsRates) > 0:
        for i in range(len(subsRates)):
            dl_rate_Mbps = int(subsRates[i][3])/1000
            ul_rate_Mbps = int(subsRates[i][4])/1000

            if(dl_rate_Mbps - int(dl_rate_Mbps) == 0):
                dl_rate_Mbps = int(dl_rate_Mbps)

            if(ul_rate_Mbps - int(ul_rate_Mbps) == 0):
                ul_rate_Mbps = int(ul_rate_Mbps)
            
            ratePlanName = str(dl_rate_Mbps) + "_" + str(ul_rate_Mbps) + "M"
            
            if not(ratePlanName in tempRatePlans):
                ratePlans.append([dl_rate_Mbps, ul_rate_Mbps, ratePlanName] )
                tempRatePlans.append(ratePlanName)
                subsRatePlansIndices.append(ratesIndex)
                ratesIndex += 1
            else:
                subsRatePlansIndices.append(tempRatePlans.index(ratePlanName))

    return ratePlans, subsRatePlansIndices


def addUpdatePoliciesFromFile(ratePlans, acm):
    print_stderr("Updating rate plans from file\n")

    for i in range(len(ratePlans)):
        rates = ratePlans[i]

        rateDL = int(rates[0] * 1000)  # Plans are in Mbps, QoE accepts kbps
        rateUL = int(rates[1] * 1000)  # Plans are in Mbps, QoE accepts kbps
        policyName = rates[2] 
        policyId = policyName

        addPolicy(policyName, rateDL, rateUL, policyId, acm)


def assignRatePlansToSubscribers(subsRates, ratePlans, subsRatePlanIndices):
    print_stderr("Assigning Subscribers to rate plans from file\n")
    qoutaDetails = []
    for i in range(len(subsRates)):
        qoutaDetails = [0,0,0]
        policyName = ratePlans[subsRatePlanIndices[i]][2] 
        subscriber = subsRates[i][2]
        if(subsRates[i][0].strip() == "" and subsRates[i][1].strip() == "" ): # Both Customer Number & Name are empty
            subscriberIdTxt = subscriber  # set subscriberID as the subscriber IP
        elif (subsRates[i][0].strip() == "" and subsRates[i][1].strip() != "" ): # Customer Number is empty
            subscriberIdTxt = subsRates[i][1] # set ID as Customer Name
        elif(subsRates[i][0].strip() != "" and subsRates[i][1].strip() == "" ): # Customer Name is empty
            subscriberIdTxt = subsRates[i][0] # set ID as Customer Number
        else: # Both Customer Number & Name are not empty
            subscriberIdTxt = subsRates[i][0]+"-"+subsRates[i][1]  # Set SubscriberId as CustomerNumber_CustomerName

        subscriberIdTxt = subscriberIdTxt.replace(" ", "_")

        qoutaEnabled = int(subsRates[i][5])
        if qoutaEnabled > 0:
            qoutaDetails[0] = int(subsRates[i][6]) # int(time.time())+(10*365*24*60*60)
            quota_exp_time = int(subsRates[i][6]) # int(time.time())+(10*365*24*60*60)

            qoutaDetails[1] = int(subsRates[i][7]) # Qouta Volume KB
            quota_kB = int(subsRates[i][7])  # Qouta Volume KB

            qoutaDetails[2] = int(subsRates[i][8]) # Qouta Volume Increment KB
            quota_inc_kB = int(subsRates[i][8]) # Qouta Volume Increment KB

        policyName = standarizePolicyName(policyName)
        assignSubscriberToRatePolicy(subscriber, subscriberIdTxt, policyName, qoutaEnabled, qoutaDetails) # quota_exp_time, quota_kB, quota_inc_kB)


def displaygetloadSubRatePlansFromFileUsage():
    print_stderr("\nUsage:")
    print_stderr(os.path.basename(__file__) + " loadSubsFromFile -f [File Name] [-acm [true|false]] [cfg [qoe access configuration file name]]")
    print_stderr("")

def loadSubRatePlansFromFile(args):

    print_stderr("Getting subscriber metrics through CLI")
    #print_stderr(args)
    if args.subs_rate_plans_file is None:
        print_stderr("Missing subscribers rate plans file")
        displaygetloadSubRatePlansFromFileUsage()
        return -1
    
    if does_file_exist(str(args.subs_rate_plans_file)) == False:
        print_stderr ("\n\nERROR ==> File [", str(args.subs_rate_plans_file ), "] does not exist")
        displaygetloadSubRatePlansFromFileUsage()
        return(-1)
    
    acm = True # Defatul ACM is ON
    if args.acm is not None:
        if args.acm.lower() == "false":
            acm = False

    subsRates = read_subs_plans(args.subs_rate_plans_file)
    ratePlans, subsRatePlanIndices = find_all_rate_plans(subsRates)
    addUpdatePoliciesFromFile(ratePlans, acm)
    assignRatePlansToSubscribers(subsRates, ratePlans, subsRatePlanIndices)



######################################################################
################                                        ##############
################                main()                  ##############
################                                        ##############
######################################################################


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("action", help="Action to be performed: addPolicy|getPolicy|deletePolicy|setSubRatePolicy|getSubRatePolicy|deleteSubRatePolicy|getSubMetrics|loadSubsFromFile")
    parser.add_argument("-p", "--policyName", help="Policy Name, no spaces or special characters")
    parser.add_argument("-pi", "--policyId", help="Policy Identifier, no spaces or special characters")
    parser.add_argument("-dl", "--downlinkRate", type=int, help="Downlink rate in kbps")
    parser.add_argument("-ul", "--uplinkRate", type=int, help="Uplink rate in kbps")
    parser.add_argument("-acm", "--acm", help="Automatic Congestion Management (ACM) enabled: true/false")
    parser.add_argument("-s", "--subscriber", help="subscriber IP address, IPv4 only")
    parser.add_argument("-si", "--subscriberId", help="subscriber Id")
    parser.add_argument("-m", "--metric", help="subscriber metric to retrieve: bandwidth|flows|latency|retransmission|volume")
    parser.add_argument("-mi", "--metric_interval", type=int, help="subscriber metric time interval in minutes (default 60 minutes)")
    parser.add_argument("-mp", "--metric_period", type=int, help="subscriber metric ime period in hours (default: 24 hours). The maximum query period is 3 months")
    parser.add_argument("-f", "--subs_rate_plans_file", help="subscriber rate plans file name")
    parser.add_argument("-cfg", "--qoe_access_config_file", help="QoE REST Configuration file name")
    

    args = parser.parse_args()

    read_qoe_rest_access_info(args.qoe_access_config_file)

    match args.action.lower():
        case "addpolicy":
            return addPolicyFromCLI(args)
        case "getpolicy":
            return getPolicyFromCLI(args)
        case "deletepolicy":
            return deletePolicyFromCLI(args)
        case "setsubratepolicy":
            return setSubRatePolicyFromCLI(args)
        case "getsubratepolicy":
            return getSubRatePolicyFromCLI(args)
        case "deletesubratepolicy":
            return deleteSubRatePolicyFromCLI(args)
        case "getsubmetrics":
            return getSubMetricsFromCLI(args)
        case "loadsubsfromfile":
            return loadSubRatePlansFromFile(args)
        case default:
            print_stderr("ERROR:: Unknow action ==> ", args.action)
            print_stderr("Supported actions ==> ", "addPolicy | getPolicy | deletePolicy | setSubRatePolicy | getSubRatePolicy | deleteSubRatePolicy | getSubMetrics | loadSubsFromFile")
            parser.print_help()
            return -1



if __name__ == '__main__':
    main()

