
#!/usr/pkg/bin/python

import json
import requests
import os
import sys
import argparse
from optparse import OptionParser
import csv
import re
from datetime import datetime, timezone
import pytz

## Supress HTTPS Insecure Request warning
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Define a regular expression pattern to match numbers -- for DL & UL Rate extraction from plan name
service_name_pattern = r'(\d+)-(\d+)'


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


DL_RATE_MULTIPLIER = 1.0
UL_RATE_MULTIPLIER = 1.0

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
#    print(*args, file=sys.stderr, **kwargs)
    print(*args, **kwargs)


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
            print_stderr(json.dumps(response.json(), indent=4))
    return response.status_code


def standarizeName(Name):
    Name = Name.strip()
    Name = Name.replace(' ', '-')
    Name = Name.replace('/', '_')
    Name = Name.replace('\\', '_')
    Name = Name.replace('+', '_')
    Name = Name.replace(';', '_')
    Name = Name.replace(',', '_')
    Name = Name.replace(':', '_')
    Name = Name.replace('@', '_')
    Name = Name.replace('#', '_')
    Name = Name.replace('$', '_')
    Name = Name.replace('%', '_')
    Name = Name.replace('!', '_')
    Name = Name.replace('~', '_')
    Name = Name.replace('&', '_')
    Name = Name.replace('^', '_')
    Name = Name.replace('"', '_')
    Name = Name.replace('\'', '_')
    Name = Name.replace('*', '_')
    
    return Name


def addPolicy(policyName, downlinkRate, uplinkRate, policyId, acm):
    #### Add new Policy

    policyName = standarizeName(policyName)
    
    if downlinkRate is not None:
        downlinkRate = int(downlinkRate) # remove fraction from rate
    else:
        downlinkRate = -1

    if uplinkRate is not None:
        uplinkRate = int(uplinkRate) # remove fraction from rate
    else:
        uplinkRate = -1

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


def assignSubscriberToRatePolicy(subscriberRecord, newSub = True):
    #### Assign Subscriber to a policy

    subscriber = subscriberRecord['subscriberIp']
    subscriberId = subscriberRecord['subscriberId']
    policyName = subscriberRecord['policyName']
    subscriberGroups = subscriberRecord['subscriberGroups']
    quota_details = subscriberRecord["quotaDetails"]
    

    print_stderr(f'Adding policy {policyName} for subscriber {subscriber}')
    headers = {
        # Already added when you pass json=
        'Content-Type': 'application/json',
        "Accept-Charset": "UTF-8"
    }
    
    
    json_data = {
        'policyRate': policyName,
        'subscriberId': subscriberId,
    }

    quota_dict = {}

    if quota_details is not None:
        quota_enabled = False
        
        if(quota_details[0] > 0):
            quota_dict['time'] = quota_details[0]
            quota_enabled = True
        if(quota_details[2] > 0 ): # if volume is present it overwites volumeIncrement, so check volumeIncrement first, if it is > 0 then ignore the volume field.
                                    # user is trying to increase the quota by the volumeIncrement value.
            quota_dict['volumeIncrement'] = quota_details[2]
            quota_enabled = True
        elif(quota_details[1] > 0):
            quota_dict['volume'] = quota_details[1]
            quota_enabled = True

        if quota_enabled:
            json_data['quota'] = quota_dict

    if subscriberGroups is not None and len(subscriberGroups) > 0:
        json_data['subscriberGroups'] = subscriberGroups

    if newSub:
        # subscriber does not exist .. use POST method
        response = requests.post(URL_PREFIX + 'subscribers/' + subscriber, headers=headers, json=json_data, verify=False, auth=(QoE_REST_USER, QoE_REST_PASSWORD))
    else:  # subscriber exists .. use PUT method
        response = requests.put(URL_PREFIX + 'subscribers/' + subscriber, headers=headers, json=json_data, verify=False, auth=(QoE_REST_USER, QoE_REST_PASSWORD))

    if(processResponse(response) >= 400):
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
    errorTxt =" setSubRatePolicy --subscriber [IPv4] --subscriberId [ID] --policyName [policyname] -qt [Quota Details] -grps [Subscriber Groups]\n\n"
    errorTxt += " -qt [':' separated numbers formatted as ExpirationDate:ExpirationTime:Volume(kBytes):VolumeIncrement(kBytes). e.g. 2023-12-30:23-30:90000000:0 for 90GB quota expiring on Dec 30th 2023 at 11:30 PM]\n"
    errorTxt += "\t\tExpirationDate format: YYYY-MM-DD  or 0 for no expiration date\n"
    errorTxt += "\t\tExpirationTime format: HH-MM or 0 for no expiration time. Set to 0 if no expiration date\n"
    errorTxt += " -grps [':' separated groups names up to 8 groups ':' separated e.g. AP1NorthWest:Site1Noth:'Tower1 North West']\n"
    errorTxt += "\t\t use '' for group name that includes spaces. \n"
    errorTxt += "\t\t ':' can not be part of a group name'.\n"
    errorTxt += "\n Optional parameters: --subscriberId, -qt and -grps"
    
    print_stderr(os.path.basename(__file__) + errorTxt)
    print_stderr("")
 
def is_valid_date(date_string):
    try:
        # Attempt to parse the string as a date
        datetime.strptime(date_string, "%Y-%m-%d")
        return True
    except ValueError:
        # If parsing fails, it's not a valid date
        return False

def convertExpirationDateTimetoUTC(quota_expir_date, quota_expir_time):
    utc_exp_time = 0

    if quota_expir_date is None :
        return 0
    
    if not is_valid_date(quota_expir_date):
        return 0

    if quota_expir_time is None or quota_expir_time == "":
        quota_expir_time = "00-00"

    #if str(quota_expir_date) != "0":

    expiration_time = quota_expir_time.split("-")
    if len(expiration_time) < 2:
        expiration_str = quota_expir_date + " " + "00:00"
    else:
        expiration_str = quota_expir_date + " " + expiration_time[0] +":"+expiration_time[1]

    expiration_datetime = datetime.strptime(expiration_str, "%Y-%m-%d %H:%M")

    local_timezone = datetime.now(timezone.utc).astimezone().tzinfo
    local_exp_datetime = expiration_datetime.replace(tzinfo=local_timezone)
    
    utc_timezone = pytz.utc
    utc_exp_datetime = local_exp_datetime.astimezone(utc_timezone)

    utc_exp_time = int(utc_exp_datetime.timestamp())

    return utc_exp_time
 
def process_quota_values(sub_quota):
    quotaDetails = None
    newSubscriber = True

    quota_values = sub_quota.split(":")
    if len(quota_values) == 4:

        quota_expir_date = quota_values[0]
        quota_expir_time = quota_values[1]
        quota_volume = int(quota_values[2])
        quota_volume_increment = int(quota_values[3])


        quota_expiration_utc = convertExpirationDateTimetoUTC(quota_expir_date, quota_expir_time)

        quotaDetails = [quota_expiration_utc, quota_volume, quota_volume_increment]

        if quota_volume_increment > 0: 
            newSubscriber = False
    else:
        return -1
    
    return 1, quotaDetails, newSubscriber

def process_subscriber_groups(sub_groups):
    subscriberParentSites = None
    groups = sub_groups.split(":")
    if len(groups) > 0:
        subscriberParentSites = []
        for group in groups:
            group = standarizeName(group)
            if group not in subscriberParentSites:
                subscriberParentSites.append(group)
    else:
        return -1

    return 1, subscriberParentSites

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
        subscriberIdTxt = args.subscriber
    else:
        subscriberIdTxt = args.subscriberId

    subscriberParentSites = None 
    quotaDetails = None
    newSubscriber = True
    ## Process quota info if provided
    if args.sub_quota_list is not None:
        sub_quota = args.sub_quota_list
        status, quotaDetails, newSubscriber = process_quota_values(sub_quota)
        if status == -1:
            print_stderr("Missformatted subscriber quota field")
            displaySetSubRatePolicyUsage()
            return -1

    ## Process subscriber groups info if provided
    if args.sub_group_list is not None:
        sub_groups = args.sub_group_list
        status, subscriberParentSites = process_subscriber_groups(sub_groups)
        if status == -1:
            print_stderr("Missformatted subscriber groups field")
            displaySetSubRatePolicyUsage()
            return -1



    subscriberRecord = []

    policyName = standarizeName(args.policyName)
    subscriberIdTxt = standarizeName(subscriberIdTxt)
    subscriberIp = args.subscriber
    subscriberRecord = {'subscriberIp': subscriberIp, 'subscriberId': subscriberIdTxt, 
                        'policyName': policyName, 'subscriberGroups': subscriberParentSites,
                        'quotaDetails': quotaDetails}
    
    return assignSubscriberToRatePolicy(subscriberRecord, newSub=newSubscriber)


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
        if rates[0] is not None:
            rateDL = int(rates[0])  
        else:
            rateDL = None

        if rates[1] is not None:
            rateUL = int(rates[1])  
        else:
            rateUL = None

        policyName = rates[2] 
        policyId = policyName

        addPolicy(policyName, rateDL, rateUL, policyId, acm)


def assignRatePlansToSubscribers(subsRates, ratePlans, subsRatePlanIndices):
    print_stderr("Assigning Subscribers to rate plans from file\n")
    quotaDetails = []
    for i in range(len(subsRates)):
        subscriberRecord = []
        policyName = ratePlans[subsRatePlanIndices[i]][2] 
        subscriberIp = subsRates[i][2]
        subscriberId = standarizeName(subsRates[i][0] + "-" + subsRates[i][1])

        quotaDetails = None
        newSubscriber = True
        if subsRates[i][5] is not None and subsRates[i][5].strip() !="":
            status, quotaDetails, newSubscriber = process_quota_values(subsRates[i][5])
            if status == -1:
                print_stderr("Subscriber with IP ", subscriberIp, " has missformatted quota info ... Skipping subscriber quota")

        subscriberParentSites = None

        if subsRates[i][6] is not None:
            status, subscriberParentSites = process_subscriber_groups(subsRates[i][6])
            if status == -1:
                print_stderr("Subscriber with IP ", subscriberIp, " has missformatted subscriber group info ... Skipping subscriber groups")

        subscriberRecord = {'subscriberIp': subscriberIp, 'subscriberId': subscriberId, 
                            'policyName': policyName, 'subscriberGroups': subscriberParentSites,
                            'quotaDetails': quotaDetails}
        
        assignSubscriberToRatePolicy(subscriberRecord, newSub=newSubscriber)


def displaygetloadSubRatePlansFromFileUsage():
    print_stderr("\nUsage:")
    print_stderr(os.path.basename(__file__) + " loadSubsFromFile -f [File Name] [-acm [true|false]] [cfg [qoe access configuration file name]]")
    print_stderr("")

def loadSubRatePlansFromFile(args):

    print_stderr("Reading subscriber rates from file")
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
    parser.add_argument("-grps", "--sub_group_list", help="Subscriber group list up to 8 groups ':' separated")
    parser.add_argument("-qt", "--sub_quota_list", help="Subscriber quota info ':' separated, formatted as ExpirationDate(YYYY-MM-DD):ExpirationTime(HH-MM):Volume(kBytes):VolumeIncrement(kBytes)")
    

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

