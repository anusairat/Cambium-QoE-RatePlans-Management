
#!/usr/pkg/bin/python

import json
import requests
import os
import sys
import argparse
from optparse import OptionParser



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

def processPostResponse(response):
    if("Content-Length" in response.headers and int(response.headers["Content-Length"]) > 0):
        print(json.dumps(response.json(), indent=4))
    return response.status_code

def processDeleteResponse(response):
    if("Content-Length" in response.headers and int(response.headers["Content-Length"]) > 0):
        print(json.dumps(response.json(), indent=4))
    return response.status_code

def processGetResponse(response):
    if("Content-Length" in response.headers and int(response.headers["Content-Length"]) > 0):
        print(json.dumps(response.json(), indent=4))
    return response.status_code


def addPolicy(policyName, downlinkRate, uplinkRate, policyId, acm):
    #### Add new Policy
    print_stderr("Adding new Policy ==>  Name: {:s} Id: {:s} DL Rate(kbps): {:d} UL Rate (kbps): {:d}  ACM: {:s}".format(policyName, policyId, downlinkRate, uplinkRate, str(acm)))
    headers = {
        # Already added when you pass json= but not when you pass data=
        # 'Content-Type': 'application/json',
    }

    json_data = {
        'policyId': policyId,
    }

    if(downlinkRate > 0):
        json_data['rateLimitDownlink'] = {
            'rate': downlinkRate,
            'congestionMgmt': acm,
        }
    else:
        json_data['rateLimitDownlink'] = {
            'congestionMgmt': acm,
        }

    if(uplinkRate > 0):
        json_data['rateLimitUplink'] = {
            'rate': uplinkRate,
        }


    response = requests.post(URL_PREFIX + 'policies/rate/' + policyName, headers=headers, json=json_data, verify=False, auth=(QoE_REST_USER, QoE_REST_PASSWORD))
    if(processPostResponse(response) >= 400):
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

    if(processGetResponse(response) >= 400):
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
    if(processDeleteResponse(response) >= 400):
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
    if(processDeleteResponse(response) >= 400):
        #print_stderr("Error deleting policies with Id  %s\n" %policyId)
        return -1
    return 0


def assignSubscriberToRatePolicy(subscriber, subscriberId, policyName):
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
    response = requests.post(URL_PREFIX + 'subscribers/' + subscriber, headers=headers, json=json_data, verify=False, auth=(QoE_REST_USER, QoE_REST_PASSWORD))
    if(processPostResponse(response) >= 400):
        #print_stderr("Error assiging Policy to the subscriber\n")
        return -1

    return 0


def retrieveSubscriberRatePolicy(subscriber):

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
    if(processGetResponse(response) >= 400):
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
    if(processDeleteResponse(response) >= 400):
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
    if(processDeleteResponse(response) >= 400):
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
    if(processGetResponse(response) >= 400):
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


    acm = False
    if args.acm is None:
        acm = False
    elif args.acm.lower() == "true":
        acm = True
    elif args.acm.lower() == "false":
        acm = False
    else:
        print("Wrong ACM switch value")
        displayAddPolicyUsage()
        return -1


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

    return assignSubscriberToRatePolicy(args.subscriber, args.subscriberId, args.policyName)

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


######################################################################
################                                        ##############
################                main()                  ##############
################                                        ##############
######################################################################


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("action", help="Action to be performed: addPolicy|getPolicy|deletePolicy|setSubRatePolicy|getSubRatePolicy|deleteSubRatePolicy|getSubMetrics")
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

    args = parser.parse_args()

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
        case default:
            print_stderr("ERROR:: Unknow action ==> ", args.action)
            parser.print_help()
            return -1



if __name__ == '__main__':
    main()

