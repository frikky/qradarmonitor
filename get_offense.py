import os
import re
import sys
import ast
import json
import time
import time
import socket
import logging
import netaddr
import datetime
import pickledb
import requests
import subprocess

"""
	The part below is setitng up default logging, 
	certificates, disabling uneccesary warnings etc.
"""
dir_path = os.path.dirname(os.path.realpath(__file__))

sys.path.append('%s/dependencies' % dir_path)
from customer import Customer
import urllib
#from urllib import urllib.quote

# Add multiple logging systems.
requests.packages.urllib3.disable_warnings(\
requests.packages.urllib3.exceptions.InsecureRequestWarning)


log_path = "%s/log/" % dir_path
if not os.path.exists(log_path):
    os.makedirs(log_path)
    open("%salarm.log" % (log_path), "w+").close()

try:
    logging.basicConfig(filename='%s/log/alarm.log' % dir_path, level=logging.DEBUG)
    if len(sys.argv) > 1: 
        if sys.argv[1] == "--verbose" or sys.argv[1] == "-v":	
        	os.system('cls' if os.name == 'nt' else 'clear')
except IOError as e:
    print("Might be missing permissions.\n%s" % e)
    try:
        sys.exit(0)
    except SystemExit:
        os._exit(0)

logging.getLogger("requests").setLevel(logging.INFO)
logging.getLogger("urllib3").setLevel(logging.INFO)

json_time = 0

class Offense(object):
    """
		Class used for handling offenses and customers. 
		Uses customer.py to handle each and every customer in the configuration file.
    """
    def __init__(self):
        self.customers = []
        self.db_status = False
        self.mobile_db = ""

    # Function only in use when either customer_values.db does not exists or is empty
    def db_setup(self):
        """
			Creates db for a customer if it doesn't exist.	
        """
        database = "%s/database/customer_values.db" % dir_path
        if not os.path.isfile(database):
            open(database, 'w+').close()

        try:
            self.db = pickledb.load(database, False)
        except pickledb.simplejson.scanner.JSONDecodeError:
            # Remove file, and recreate
            os.remove(database)
            logging.info("Creating database")
            self.db = pickledb.load(database, False)

        
    # Creates folders for customers.
    def create_customer_folder(self, customer_name):
        """
			Creates a directory for a customer to save offenses. Used for backlogging.
        """
        customer_dir = "%s/database/customers/%s" % (dir_path, customer_name )
        if not os.path.exists(customer_dir):
            os.makedirs(customer_dir)

        
    # Creates database for customer if it doesnt exist and SEC token exists
    def create_db(self, name):
        """
			Uses pickledb to keep track of latest offenses.
        """
        self.db_setup()
        self.create_customer_folder(name)
        if not name in self.db.getall():
            self.db.lcreate(name)
            self.db.ladd(name, 0)
            self.db.set(name+"_counter", 0)
            self.db.set(name+"_status_code", 200)
            self.db.set(name+"_code_status", 0)
            self.db.dump()
            logging.info("%s Initialized database for %s" % (self.get_time, name))
            return False
        return True

    # Gets current time for print format.
    def get_time(self):
        return time.strftime("%H:%M:%S")

    # Reloading the complete customers object for every iteration
    def add_customers(self, customer_json):
        """
			Creates customer object => Loops through each and every one 
			and verifies if they exist or not in the customer list. (self.customers)
        """

        self.customers = []
        # Catches exception related to unbound variables
        try:
            for item in customer_json:
                try:
                    # Verifies Json data
                    if item['SEC'] and len(item['SEC']) is 36:
                        a = Customer(item['name'], item['SEC'], \
                                     item['target'], item['version'], \
                                     item['rules'], item['subnet'], \
                                     item['cert'], item['domain'])
                        logging.info("%s: Customer %s added/reloaded to customer" % (self.get_time(), item['name']))
                        self.create_db(item['name'])
                        self.customers.append(a)
                    else:
                        logging.info("%s: No SEC token found for %s" % (self.get_time(), item['name']))
                except KeyError as e:
                    logging.warning("%s: Bad key: %s" % (self.get_time(), e))
                    continue
        except UnboundLocalError:
            return

    # Checks if the json is valid with expected inputs
    def load_objects(self, customers = []):
        """
			Verifies if the JSON interpreted contains errors and if it should be refreshed or not.
			THis function exists to make real-time addition of new customers possible.
        """
        global json_time
        file = "%s/database/customer.json" % dir_path

        # Verifies if file has been edited.
        if os.path.getmtime(file) > json_time:
            json_time = os.path.getmtime(file)
            msg = "%s: Reloading %s because of timedifference" % (self.get_time(), file)
            if len(sys.argv) > 1:
                if sys.argv[1] == "--verbose" or sys.argv[1] == "-v":	
                	print(msg)

            self.write_offense_log(msg) 

            logging.info("%s: Reloading %s because of timedifference" % (self.get_time(), file))
        else:
            logging.info("%s: No changes made to %s" % (self.get_time(), file))
            return

        try:
            with open(file, 'r') as tmp: 
                #self.verify_json(open(file, 'r'))
                customer_json = json.loads(tmp.read())
        except IOError as e:
            logging.info("%s: %s" % (self.get_time(), e))
            return
        except ValueError as e:
            logging.info("%s: %s" % (self.get_time(), e))
            return 

        # Create customer info 
        customer_value = self.add_customers(customer_json)
        return customer_value
        
    # Uses Sveve for SMS sending
    def send_sms(self, message):
        """
			Originally made to send an SMS with the message variable to a specific number.
        """
        logging.info("%s: %s" % (self.get_time(), "Attempting to send sms"))

        if isinstance(message, dict):
            message = "\n".join(message['categories'])

        passwd=""

        # Measure to not make api calls for SMS service.
        if not passwd:
            logging.info("%s: %s" % (self.get_time(), "Aborting sms sending"))
            return

        username = "hmm /o\\"
        url = "https://sveve.no/SMS/SendMessage?"
        target = ""
        sender = "IT ME"

        tot_url = "%suser=%s&passwd=%s&to=%s&from=%s&msg=%s - %s" % (url, username, passwd, target, sender,  message['id'], message)
        tot_url += "%20SMS"
        logging.info("%s: should send alarm for ****\n%s" % (self.get_time(), tot_url))

        try:
            request = requests.get(tot_url, timeout=5, verify=False)
        except (requests.exceptions.ConnectionError,\
                requests.exceptions.ReadTimeout,\
                AttributeError) as e:
            logging.warning("%s: %s" % (self.get_time(), e))

        return 

    # Runs the alarm
    def run_alarm(self, item, customer):
        """
			Originally used to control on-screen, but later found to be annoying.
			CUrrently not in use. 
        """
        logging.info("%s: New highest offense - %s - customer %s, %s" % \
            (self.get_time(), item['id'], customer.name, item['categories']))

        if self.db.get(customer.name+"_counter") is 0:
            self.db.set(customer.name+"_counter", \
            int(self.db.get(customer.name+"_counter"))+1)
            return

        logging.warning("%s: Sending alarm to %s" % (self.get_time(), customer.name))
        new_data = urllib.quote("Offense #%s: %s" % \
                            (item['id'], "\n".join(item['categories'])))

        """
        try:
            requests.get("http://127.0.0.1:5000/notify?message=%s" % new_data, timeout=5)
        except (requests.exceptions.ConnectionError,\
                requests.exceptions.ReadTimeout,\
                AttributeError) as e:
            logging.warning("%s: %s" % (self.get_time(), e))
        """

        # Return to only get one alarm at a time per customer.
        return False

    def reverse_list(self, customer, request):
        """
			Reverses a list. QRadar API > 7.0 wasn't stable.
        """
        tmp_arr = []
        if not customer.new_version:
            for i in range(len(request.json())-1, -1, -1):
                tmp_arr.append(request.json()[i])
            return tmp_arr
        else:
            return request.json()

    def id_to_ip(self, ID, id_list, customer, src_dst):
        """
			Finds an IP based on the ID injected through QRadar API calls.
        """
        ip_to_return = ""
        if id_list.json()["number_of_elements"] is 0:
            if src_dst == "src":
                id_list = self.get_reflist(customer, customer.src_id_list)
            elif src_dst == "dst":
                id_list = self.get_reflist(customer, customer.dst_id_list)

        if id_list.json()["number_of_elements"] is 0:
            logging.info("%s: Reflist %s is empty" % (self.get_time(), id_list.json()["name"]))
            return False

        for item in id_list.json()["data"]:
            if item["value"].startswith("%d" % ID):
                ip_to_return = ast.literal_eval(("{"+item["value"]+"}").replace("'", "\""))
                if type(ip_to_return) is dict:
                    try:
                        return ip_to_return[ID]
                    except KeyError as e:
                        return False
                else:
                    return False

        return False


    # Removes the "Range" header for some specific API calls.
    def remove_range_header(self, customer):
        """
			Removes a specific header. Depends on which API call is used.
        """
        headers = dict.copy(customer.header)

        try:
            del headers["Range"] 
        except KeyError as e:
            logging.warning("%s: Bad key: %s" % (self.get_time(), e))
        return headers

    # If it doesn't exist already
    def find_ip(self, customer, ID, headers):
        """
			Finds and IP based on ID.
			Almost same as above, but not in bulk.
        """
        target_path = "https://%s/api/siem/source_addresses" % customer.target

        try:
            find_ip = requests.get(target_path+"/%s?fields=id,source_ip" % \
                str(ID), headers=headers, timeout=5, verify=False)
        except (requests.exceptions.ConnectionError,\
                requests.exceptions.ReadTimeout,\
                AttributeError) as e:
            logging.warning("%s: %s" % (self.get_time(), e))

        try:
            ret_val = find_ip.json()["source_ip"]
        except KeyError as e:
            ret_val = False

        return ret_val

    def create_single_ID(self, customer, ID, src_dst):
        """
			Creates an ID based on an IP.	
        """
        headers = self.remove_range_header(customer)

        src_ID = "https://%s/api/siem/%s" % (customer.target, "source_addresses" \
                 if src_dst == "src" else "local_destination_addresses")
        
        ip = self.find_ip(customer, ID, headers)

        if ip is False:
            return 
        
        try:
            add_ID_to_set = requests.post(\
                "https://%s/api/reference_data/sets/%s?value=%s: '%s'" \
                % (customer.target, customer.src_id_list if src_dst == "src" else customer.dst_id_list, ID, ip), \
                headers=headers, timeout=5, verify=False)
        except (requests.exceptions.ConnectionError,\
                requests.exceptions.ReadTimeout,\
                AttributeError) as e:
            logging.warning("%s: %s" % (self.get_time(), e))


    # Creates a bulk of items (if list is empty)
    def create_ID_list(self, customer, id_list_name, src_dst):
        """
			Creates a bulk of items and pushes them to specified 
			reference set for bulk extraction. Deprecated.
        """
        ID_arr = []
        headers = self.remove_range_header(customer)
        req = ""
        
        if src_dst is "src":
            field = "source_ip" 
            src_ID = "https://%s/api/siem/source_addresses%s" % (customer.target, src_ID_fields)
        elif src_dst is "dst":
            field = "local_destination_ip"
            src_ID = "https://%s/api/siem/local_destination_addresses" % customer.target

        # Bulkloading from src/dst IDs available.
        #try:
        #print "Making request %s" % src_ID
        req = requests.get(src_ID, headers=headers, timeout=10, verify=False)
        #except (requests.exceptions.ConnectionError,\
        #        requests.exceptions.ReadTimeout,\
        #        AttributeError) as e:
        #    logging.warning("%s: %s" % (self.get_time(), e))

        #print req.json()
        #print id_list_name
        sys.exit()
        if not req:
            return False  


        for items in req.json():
            ID_arr.append(items["id"])

        # Bulkpushing to reference set specified in customer.json
        cnt = 0
        IP_arr = []
        for item in ID_arr:
            try:
                url = src_ID+"/%s?fields=%s" % (str(item), field)
                req = requests.get(url, headers=headers, timeout=5, verify=False)
            except (requests.exceptions.ConnectionError,\
                    requests.exceptions.ReadTimeout,\
                    AttributeError) as e:
                logging.warning("%s: %s" % (self.get_time(), e))

            #if cnt is 0: 
                #print "Done in approx "+str(len(ID_arr)*req.elapsed.total_seconds()) + "seconds."
                    
            IP_arr.append("\""+str(item)+": " + "\'" + req.json()[field]+"\'\"")
            cnt += 1

        data = "["+", ".join(IP_arr)+"]"
        
        new_url = "https://%s/api/reference_data/sets/bulk_load/%s" % (customer.target, id_list_name)

        try:
            req = requests.post("%s" % new_url, data=str(data), headers=headers, timeout=5, verify=False)
        except (requests.exceptions.ConnectionError,\
                requests.exceptions.ReadTimeout,\
                AttributeError) as e:
            logging.warning("%s: %s" % (self.get_time(), e))

        try:
            if req.json()["message"].startswith("User has"):
            	msg = "Missing permissions for %s in ref set %s" % (customer.name, id_list_name)
            	if len(sys.argv) > 1:
            		if sys.argv[1] == "--verbose" or sys.argv[1] == "-v":	
            			print(msg)
            	self.write_offense_log(msg) 
				
        except KeyError as e:
            logging.warning("Added to db %s for %s" % (id_list_name, customer.name))

        return ID_arr
        

    # Creates a list of IDs
    def get_ID_list_keys(self, customer, id_request, id_list_name, src_dst):
        """
			Returns a list of IDs based on input	
        """
        id_list = []

        if id_request.json()["number_of_elements"] is 0:
            id_list = self.create_ID_list(customer, id_list_name, src_dst)

        if not id_list:
            try:
                for data in id_request.json()["data"]:
                    id_list.append(str(data["value"]).split(":")[0])
            except KeyError as e:
                logging.warning("%s: %s" % (self.get_time(), e))
                return False

        return id_list

    # Gets the a list of IDs related to IPs 
    def get_reflist(self, customer, ref_name):
        """
			Gets the actual data used to correlate with customer.json rules.
        """
        fields = ""
        headers = self.remove_range_header(customer)
        #    fields = "?fields=source_ip"
        
        ref_list = "https://%s/api/reference_data/sets/%s" % (customer.target, ref_name) 

        try:
            ref_set = requests.get("%s" % ref_list, headers=headers, timeout=5, verify=False)
        except (requests.exceptions.ConnectionError,\
                requests.exceptions.ReadTimeout,\
                AttributeError) as e:
            logging.warning("%s: %s" % (self.get_time(), e))

        return ref_set

    def get_network_list(self, network_list):
        """
			Finds the list of networks that are more valuable (e.g. server network)
        """
        arr = []
        for subnet in network_list:
            arr.append(subnet["value"])

        return arr

    # Returns 
    def get_affected_subnet(self, req, customer, network_list, id_list_name, src_dst):
        """
			Checks if the network found in an offense is part of the actual subnet
        """
        affected_subnet = []
        headers = self.remove_range_header(customer)

        if src_dst == "dst":
            ip_variable = "local_destination_ip"
            base_url = "https://%s/api/siem/local_destination_addresses/" % customer.target
            fields = "?fields=local_destination_ip" 
        elif src_dst == "src":
            ip_variable = "source_ip"
            base_url = "https://%s/api/siem/source_addresses/" % customer.target
            fields = "?fields=source_ip" 

        for ID in req.json()[id_list_name]:
            url = base_url+str(ID)+fields
            cnt = 0

            # Loop through CIDR ranges
            #ip = self.id_to_ip(ID, global_ip_ids, customer, src_dst)

            ip = requests.get(url, headers=headers, verify=False)
            try:
                ip = ip.json()[ip_variable]
            except KeyError as e:
                logging.warning("%s: %s" % (self.get_time(), e))
                continue

            for network in network_list:
                try:
                    if ip in netaddr.IPNetwork(network):
                        return ip

                except netaddr.core.AddrFormatError as e:
                    logging.warning("%s: %s" % (self.get_time(), e))
                    cnt += 1

        return False
        #return affected_subnet


    # Verifies alarms related to reference lists
    def verify_reflist(self, customer, req):
        """
			Verifies multiple reference set alarms. 
        """
        #self.verify_direction(customer, req)

        id_list = ["source_address_ids", "local_destination_address_ids"]
    
        affected_subnet = []
        # Get global source_address_ids first

        """
        # Remove because of change of plans \o/
        src_ip_ids = self.get_reflist(customer, customer.src_id_list)
        dst_ip_ids = self.get_reflist(customer, customer.dst_id_list)

        # Need admin access? Wat
        # ALRIGHTY THEN
        if not src_ip_ids.status_code is 200 or not src_ip_ids.status_code is 200:
            print "Might be insufficient permissions for %s" % customer.name
            print "%s: %s" % (self.get_time(), src_ip_ids.json()["message"])
            return False

        src_ID_list = self.get_ID_list_keys(customer, src_ip_ids, customer.src_id_list, "src")
        dst_ID_list = self.get_ID_list_keys(customer, dst_ip_ids, customer.dst_id_list, "dst")
        """

        # List of subnets to check
        for ref_set_list in customer.ref_list:
            ref_set = self.get_reflist(customer, ref_set_list)

            # Works because < 255
            if not ref_set.status_code is 200:
                logging.warning("Cannot access reflist.")
                continue

            try:
                network_list = self.get_network_list(ref_set.json()["data"])
            except KeyError as e:
                logging.warning("%s: %s" % (self.get_time(), e))
                if ref_set.json()["number_of_elements"] is 0:
                    msg = "%s might be empty for %s, no action taken." \
                            % (ref_set_list, customer.name)

                    if len(sys.argv) > 1:
                    	if sys.argv[1] == "--verbose" or sys.argv[1] == "-v":	
                    		print(msg)

                    self.write_offense_log(msg) 
					

                continue

            src_affected_subnet = self.get_affected_subnet(req, customer, \
                    network_list, "source_address_ids", "src")
            if src_affected_subnet:
                #sys.stdout.write("SUBNET %s. " % src_affected_subnet)
                return True

            dst_affected_subnet = self.get_affected_subnet(req, customer, \
                    network_list, "local_destination_address_ids", "dst")

            if dst_affected_subnet:
                #sys.stdout.write("SUBNET %s. " % src_affected_subnet)
                return True

        return False

    def check_alarm(self, ID, customer):
        """
			Verifies an ID, if it's new etc. Bulk loads and checks if the lowest number 
			is greater than the oldest saved one.
			The horrible forloop verifies if rules are matched based on rules in customer.json
        """
        fields = ""
        valid = True 

        headers = self.remove_range_header(customer)

        try:
            req = requests.get("https://%s/api/siem/offenses/%s%s" % (customer.target, str(ID), fields),\
                     timeout=5, headers=headers, verify=False) 
        except (requests.exceptions.ConnectionError,\
                requests.exceptions.ReadTimeout,\
                AttributeError) as e:
            logging.warning("%s: %s" % (self.get_time(), e))

        if req.status_code != 200:
            logging.warning("%s Unable to retrieve %s" % (self.get_time(), customer.target))
            return False

        # Checks reference lists from database/customer.json
        if customer.ref_list[0]:
            valid = self.verify_reflist(customer, req) 
        else:
            return False
    
        # Skips if reference list match
        # Can add alarm sending in this one
        
        if not valid:
            return False

        logging.info("%s: %s" % (self.get_time(), \
            "In subnet range. Verifying rules for %s" % customer.name))

        # Checks rules only if offense contains IP in specified IP range
        rule_counter = 0
        for rules in customer.rules: 
            # Iter keys inside rule
            for keys, values in rules.iteritems():
                # Do stuff if not integer values
                if not isinstance(values, int):
                    if values == ".*":
                        rule_counter += 1
                        continue
                    # Checks multiple arguments in same rule split on "|". 
                    for split_item in values.split("|"):
                        for categories in req.json()[keys]:
                            if split_item.lower().startswith("!") \
                                and split_item.lower()[1:] in categories.lower():
                                return False
                                #rule_counter -= 1

                            if split_item.lower() in categories.lower(): 
                                rule_counter += 1

                # INT CHECK
                else:
                    if req.json()[keys] > values:
                        rule_counter += 1
                    else:
                        break

            # Runs alarm if counter is high enough. 
            if rule_counter is len(rules):
                msg = "RULES MATCHED. SHOULD SEND ALARM \o/"
                if len(sys.argv) > 1:
                	if sys.argv[1] == "--verbose" or sys.argv[1] == "-v":	
                		print(msg)

                self.write_offense_log(msg) 
					
                logging.info("%s: Rule triggered - sending alarm" % self.get_time())
                self.run_alarm(req.json(), customer)
                break

            rule_counter = 0
        return True

    # Verify ID here
    def add_new_ID(self, customer, request):
        path = "database/customers/%s/%s" % (customer.name, str(request.json()["id"]))
        if not os.path.exists(path):
            with open(path, "w+") as tmp:
                json.dump(request.json(), tmp)

        logging.info("%s: Added new offense to %s" % (self.get_time(), path))


    # Kibana communcation for visualization
    def create_socket(self, customer, new_req):
        values = []
        keys = ["description", "id", "event_count", "source_network", "destination_network", "username_count", "categories"]
        values.append(customer.name)
        for key, value in new_req.json().iteritems():
            if not key in keys:
                continue

            #print key, value
            if isinstance(value, list):
                new_arr = []
                for items in value:
                    new_arr.append(items if isinstance(items, int) else str(items)) 

                value = new_arr

            word = ""
            for char in str(value):
                if not char == "\n":
                    word += char 
                    
            values.append(word.encode("utf-8"))


        msg = new_req.text
        target = '172.28.3.23'
        port = 1999

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((target, port))
            s.send(",".join(values))
            s.close()
        except socket.error as e:
            #print "Socket error %s" % e
            logging.warning("Socket error %s" % e)
            return


        #print "QUITTING AT SOCKET (KIBANA)"
        ##### TEST
        sys.exit()

    # DISCORD SETUP 
    def discord_setup(self, ID, msg):
        alarm_msg = "%s - %s" % (ID, msg)
        call = ["python3.6", "%s/dependencies/chat.py" % dir_path, "\"%s\"" % alarm_msg]
        subprocess.call(" ".join(call), shell=True)
        logging.info("%s: Message sent to discord server." % self.get_time())

    def write_offense_log(self, data):
        with open("log/offense.log", "a") as tmp:
            try:
                tmp.write("\n%s" % str(data))
            except UnicodeEncodeError as e:
                tmp.write("\nError in parsing data.\n%s" % e)

# Verifies the ID, and returns if it's not a new incident.
    def verify_ID(self, request, customer):
        # In case there are no offenses related to customer. Basically domain management.
        try:
            if float(customer.version) < 7.0:
                try:
                    json_id = request.json()[len(request.json())-1]['id']
                except (ValueError, IndexError) as e:
                    logging.warning("%s: Customer %s: %s" % (self.get_time(), customer.name, e))
                    return False
                customer.new_version = False
            else:
                json_id = request.json()[0]['id']
        except IndexError:
            logging.info("No offenses for customer.")
            return

        # Use difference between last seen offense and newest.
        last_db = self.db.lget(customer.name, self.db.llen(customer.name)-1)
        cur_array = []
        if json_id > last_db:
            difference = 1

            # Not even a point /o\
            if not json_id-last_db is difference:
                difference = json_id-last_db

            # Looping through incase of earlier crash / multiple offenses in one minute
            for i in range(json_id, last_db, -1):
                cur_var = False 
                if i in self.db.get(customer.name):
                    continue

                # Verifies if the id actually exists
                for item in request.json():
                    if i == item['id']:
                        cur_var = True
                        break

                if not cur_var:
                    continue      

                logging.info("%s: %s: New highest offense found: %d" % (self.get_time(), customer.name, i))

                target = "https://%s/api/siem/offenses/%s" % (customer.target, str(i))
                new_header = self.remove_range_header(customer)

                # Try / catch all the things
                try:
                    new_req = requests.get(target, headers=new_header, timeout=5, verify=False)
                except requests.exceptions.ConnectionError as e:
                    logging.warning("Internal alarmserver might be down: %s" % e)
                except requests.exceptions.ReadTimeout as e:
                    logging.warning("Timeout" % e)
                    #requests.get("http://127.0.0.1:5000/notify?ip=%s&id=%s&message=New unknown offense")

                # Appends current offense to database/customers/customer/ID in json format. 
                # This is to backtrack 
                self.add_new_ID(customer, new_req)

                # Kibana - uncomment to send (requires the server to be available)
                #self.create_socket(customer, new_req)

                # Adds to warning dumb if time is right.
                if self.mobile_db:
                    logging.info("%s: %s" % (self.get_time(), "HALLELUJA"))
                    self.mobile_db.set(customer.name, int(self.mobile_db.get(customer.name))+1)
                    self.mobile_db.dump()
                    #logging.warning("%s: %s" % (self.get_time(), e))

                #msg_arr.append(customer["name"]+": "+str(self.mobile_db.get(customer["name"])))
                new_req = new_req.json()

                try: 
                    # Compatibility issue if missing prerequisites.
                    new_data = urllib.quote("Offense #%s: %s" % (str(i), \
                                     "\n".join(new_req['categories'])))
                except TypeError as e:
                    logging.warning("%s: TypeError: %s" % (self.get_time(), e))
                    new_data = urllib.quote("Offense #%s: %s" % (str(i), "Arbitrary categories"))
                except KeyError as e:
                    logging.warning("%s: KeyError: %s" % (self.get_time(), e))
                    new_data = urllib.quote("Offense #%s: %s" % (str(i), "Arbitrary categories"))

                # Sends a local alarm if an alarmserver is running on the current system. 
                # Should be made into a function with (ip, id, message) as parameteres.
                # Loop through all current systems.
                """
                try:
                    internal = requests.get("http://127.0.0.1:5000/notify?ip=%s&id=%s&message=%s" \
                                 % (customer.target, i, new_data), timeout=5)
                except requests.exceptions.ConnectionError as e:
                    #print "%s: Internal alarmserver might be down: %s" % (self.get_time(), e)
                    logging.warning("Internal alarmserver might be down: %s" % e)
                except requests.exceptions.ReadTimeout as e:
                    logging.warning("Timeout" % e)
                """

                # Prints to screen. Try/catch only in case of errors.
                try:
                    msg = "%s: %s - %s - %s" % (self.get_time(), \
                        str(i).ljust(5), customer.name.ljust(10), ", ".join(new_req['categories']))
                    if len(sys.argv) > 1:
                    	if sys.argv[1] == "--verbose" or sys.argv[1] == "-v":	
                    		print(msg)

                    self.write_offense_log(msg) 
					
                except TypeError as e:
                    logging.warning("%s: TypeError: %s" % (self.get_time(), e))
                except KeyError as e:
                    logging.warning("%s: KeyError: %s" % (self.get_time(), e))

                
                # self.discord_setup(str(i), ", ".join(new_req['categories']))
                # Adding the new offense to the database, as well as 
                # verifying if an alarm should be triggered.
                difference = json_id-self.db.llen(customer.name)-1

                ## REMOVE COMMENT TO UPDATE DB
                cur_array.append(i)

                alarm_check = self.check_alarm(i, customer)
                if not alarm_check:
                    continue 

            # Adds all the data to the database
            if cur_array:
                cur_array = sorted(cur_array)

                for items in cur_array:
                    self.db.ladd(customer.name, items)

                
        else:
            return False

    # Reload json every time, and check it to prevent failures. verify_json(self, x) 
    def check_connection(self):
        for customer in self.customers:
            self.db.dump()
            domain_field = ""
            self.db.set(customer.name+"_counter", int(self.db.get(customer.name+"_counter"))+1)

            # Verifies status codes
            if not self.db.get(customer.name+"_status_code") is 200 \
                and customer.fail_counter % 10 > 0:
                continue

            # Domain management because of some bullshit.
            if customer.domain > 0:
                domain_field = "?filter=domain_id%s%d" % (r'%3D', customer.domain)

            # Makes original request per customer
            try:
                request = requests.get('%s%s' % (customer.target_path, domain_field), \
                    headers=customer.header, timeout=5, verify=False)
            except (requests.exceptions.ConnectionError,\
                    requests.exceptions.ReadTimeout,\
                    AttributeError) as e:
                try:
                    logging.info("%s: Connection failure %s. \
                                Waiting 10 minutes for %s." % \
                                (self.get_time(), e, customer.name))
                    continue
                except TypeError as e:
                    logging.warning("%s" % e)
                    self.db.set(customer.name+"_status_code", 401)
                    continue

            # Set previous status code?
            # Legacy, but doesn't hurt nothing \o/
            if request.status_code != 200:
                logging.info("%s: Not 200 for %s - %s" % (self.get_time(), customer.name, \
                            self.db.get(customer.name+"_status_code")))
                self.db.set(customer.name+"_status_code", request.status_code)
                continue
                
            # Sets previous status code in case of shutdown
            self.db.set(customer.name+"_status_code", request.status_code)

            verify_request = self.verify_ID(request, customer)
            if not verify_request: 
                continue


    ### OUTSIDE WORK REPORT
    # Appends customers
    def add_mobile_db(self, name):
        self.mobile_db.lcreate(name)
        self.mobile_db.set(name, 0)
        self.mobile_db.dump()
        logging.info("%s Initialized mobile database for %s" % (self.get_time(), name))

    # DB setup woo
    def mobile_db_setup(self):
        logging.info("%s: %s" % (self.get_time(), "initializing mobile db."))
        database = "database/mobile_values.db"
        if not os.path.isfile(database):
            open(database, 'w+').close()

        try:
            self.mobile_db = pickledb.load(database, False)
        except pickledb.simplejson.scanner.JSONDecodeError:
            self.remove_mobile_db(database)
            logging.info("Creating mobile database")
            self.mobile_db = pickledb.load(database, False)

        with open("database/customer.json", "r") as tmp:
            customer_json = json.loads(tmp.read()) 

        for customer in customer_json:
            self.add_mobile_db(customer["name"])

    # Returns offensecount loaded
    def get_mobile_offenses(self):
        msg = ""
        msg_arr = []

        self.mobile_db = pickledb.load("database/mobile_values.db", False)

        for customer in json.loads(open("database/customer.json", "r").read()):
            msg_arr.append(customer["name"]+": "+str(self.mobile_db.get(customer["name"])))

        #self.mobile_db.add(self.mobile_db.get(customer.name)+1)

        msg = ", ".join(msg_arr)
    
    def remove_mobile_db(self, db):
        os.remove(db)

    # SMS with offenseoverview PROD
    def get_date(self):
        now = time.strftime("%H") 
        weekday = datetime.datetime.today().weekday()
        cur_db = "database/mobile_values.db"

        # Turns off the alarm system
        if self.db_status is True:
            if weekday is 0 and int(now) is 7:
                msg = self.get_mobile_offenses()
                self.send_sms(msg)

                self.db_status = False
                self.remove_mobile_db(cur_db)
                self.mobile_db = ""
            return

        # Turns on the alarm system
        if weekday is 4 and int(now) >= 16:        
            if self.db_status is False:
                if os.path.isfile(cur_db):
                    self.remove_mobile_db(cur_db)
                    logging.debug("%s: %s" % (self.get_time(), "Removing db"))

                self.mobile_db_setup()
                self.db_status = True    


    # SMS with offenseoverview PROD

def loop():
    """
		Loops about every minute, base
    """
    t = Offense()

    msg = "%s: Server starting" % t.get_time()
    if len(sys.argv) > 1:
        if sys.argv[1] == "--verbose" or sys.argv[1] == "-v":	
        	print(msg)
    else:
        print("\nOffenses can be found in %s. Use -v for verbose mode." % "./log/offense.log")

    t.write_offense_log(msg) 

    logging.info("%s: Restarting script" % time.strftime("%Y:%M:%d, %H:%M:%S"))
    while(1):
        # Check for time
        t.get_date()
        test = t.load_objects()
        t.check_connection()
        time.sleep(60)

# OHAI
if __name__ == "__main__":
    try:
        loop()
    except KeyboardInterrupt:
        print('\nProgram interrupted. \"python get_offense.py\" to restart.')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)

    # Code used for testing purposes
    """
    t = Offense()
    with open("database/customer.json", "r") as tmp: 
        for item in json.load(tmp):
			# Change name to an appropriate customer name to test..
            if item["name"] == "customer_name":
                customer = Customer(item["name"], item["SEC"], item["target"], item["version"], item["rules"], item["subnet"], item["src_id_list"], item["dst_id_list"], item["cert"])
                t.check_alarm(offenseID, customer) 
    """
