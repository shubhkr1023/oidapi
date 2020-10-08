from flask import Flask,request,Response,json
import ldap,jsonify
from emailverify import everify
from phoneverify import pverify

con =ldap.initialize('ldap://10.26.38.183:3060')
#con =ldap.initialize('ldap://10.26.38.240:3060')

ldap_base = "dc=in,dc=ril,dc=com"
app = Flask(__name__)


#create user

@app.route('/create', methods=['POST'])
def create():
    if request.method == 'POST':
     try:

        con.simple_bind_s(request.authorization["username"],request.authorization["password"])
        data = request.get_json()  #converting to python dictionary

        #exit if Business Unit doesn't exist
        buFilter = "(&(objectClass=organizationalUnit)(ou=" + data['role']+ "))"
        buAttr = None
        results = con.search_s(ldap_base, ldap.SCOPE_SUBTREE,buFilter,buAttr)

        if(len(results)==0):  #business unit doesn't exist
            return Response(
            mimetype="application/json",
            response=json.dumps("User Role doesn't exist ") ,
            status=400)

        user_input=[i for(i,j) in data.items()] #key of all user input

        #verifying correct email format

        if('email' or 'managerEmailId' in user_input):

          #verify mail format only if it exists in body of user request
          if(everify(data['email'])==0 and everify(data['managerEmailId'])==0):
            rValue="Incorrect email format!"
            return Response(
            mimetype="application/json",
            response=json.dumps(rValue),
            status=400)


        #verifying correct mobile number format

        if('phone' in user_input):

          #verify mail format only if it exists in body of user request
          if(pverify(data['phone'])==0 ):
            rValue="Incorrect mobile number format!"
            return Response(
            mimetype="application/json",
            response=json.dumps(rValue),
            status=400)


        #verifying mandatory inputs from user

        #mandatory=["fullname","lastname","mobile","mCode","mail","password","businessUnit"]
        mandatory=["username","role","displayName","organization","country","email","phone","mCode","password"]
        temp = [x for x in mandatory if x in user_input]
        missing_attr=set(mandatory) - set(temp)
        if(len(missing_attr)==0): #i.e all mandatory fields are present in user input request body

                #adding user data to LDAP DIT

                dn="cn=" + data['username'] + ",ou=" + data['role']+ ",cn=users," + ldap_base
                #entry ={"cn":data['fullname'],"sn":data['lastname'],"givenName":data['firstname'],"objectClass":"inetOrgPerson","description":data['description'],"mobile":'+'+data['mCode']+data['mobile'],"mail":data['mail'],"userPassword":data['password'],"uid":data['uid']}



                entry={"cn":data['username'],"sn":data['lastname'],"givenName":data['firstname'],"displayName":data['displayName'],
                "o":data['organization'],"c":data["country"],"mobile":'+'+data['mCode']+data['phone'],"mail":data['email'],
                "userPassword":data['password'],"uid":data["empId"],"L":data["incidentId"],"employeeType":data["platform"],
                "title":data["fullname"],"description":data["role"]}
                if 'managerDomainId' in user_input:
                   entry.update({"managerid":data['managerDomainId']})
                if 'managerEmailId' in user_input:
                    entry.update({"manageremailid":data['managerEmailId']})
                if 'managerDomainId' in user_input:


                parsed_entry=[(i,bytes(j,encoding='utf-8'))for i,j in entry.items()]
                parsed_entry.append(("objectClass",[b"inetOrgPerson",b"orclUserV2"]))
                if 'accountstatus' in user_input:
                  entry.update({"orclisenabled":data['accountstatus']})
                else:
                  parsed_entry.append(("orclIsEnabled",b"ENABLED"))
                con.add_s(dn,parsed_entry)
                rValue = "Created user : " + data['username']
                return Response(
                mimetype="application/json",
                response=json.dumps(rValue),
                status=201
                     )
        else:
                #missing mandatory fields! Exit with 400
                rValue="Missing mandatory user attributes " + str(missing_attr)
                return Response(
                mimetype="application/json",
                response=json.dumps(rValue),
                status=400)



     except ldap.LDAPError as e:

        mssg = list(e.args)[0]['desc']
        print(e)
        rValue ="Error while adding user: " + mssg
        return Response(
          mimetype="application/json",
          response=json.dumps(rValue),
          status=400
        )



#delete user
#sample curl
#curl -i -X POST http://10.21.74.44:5000/delete --data '{"username":"test1.testSN1"}' -H 'Content-Type: application/json'

@app.route('/delete', methods=['POST'])
def delete():
    if request.method == 'POST':

     try:

        con.simple_bind_s(request.authorization["username"],request.authorization["password"])
        data = request.get_json()  #converting to python dictionary

        #search user to get dn
        filter = "(&(objectClass=*)(cn="+data['username']+"))"
        attr=None
        results = con.search_s(ldap_base, ldap.SCOPE_SUBTREE,filter,attr)

        #exit with 400 if user doesn't exists
        if len(results) == 0:
          return Response(
          mimetype="application/json",
          response=json.dumps("User doesn't exists") ,
          status=400
        )

        dn=results[0][0]

        con.delete_s(dn)
        rValue= "Deleted user : " + data['username']
        return Response(
          mimetype="application/json",
          response=json.dumps(rValue),
          status=204
        )


     except ldap.LDAPError as e:

        mssg = list(e.args)[0]['desc']
        rValue= "Error while deleting user " + "'"+ data['username'] + "': " + mssg
        return Response(
          mimetype="application/json",
          response=json.dumps(rValue),
          status=400
        )


#User search
#sample curl
#curl -i -X GET http://10.21.74.44:5000/search?username=test8.testSN8 -H 'Content-Type: application/json'

@app.route('/search', methods=['GET'])
def search():
    if request.method =='GET':
     try:
        con.simple_bind_s(request.authorization["username"],request.authorization["password"])
        username =request.args.get('username',"")
        filter = "(&(objectClass=*)(cn="+username+"))"
        #attr = None #to list all attribute in that DIT entry
        #attr =['cn','sn','givenName','mail','mobile','uid','displayName','o','c','initials',]
        attr =['cn','ou','givenName','sn','o','c','mail','mobile','uid','title','L','employeeType','displayName','orclisenabled','employeeType','description']

        #result is of the form
        #
        #[('dn',
        #{
        #'cn': [bytes encoded fullname in list],
        #'sn': [bytes encoded lastname],
        #'givenname': [bytes encoded firstname]
        #'description': [byte encode description]
        #'mobile': [byte encoded mobile]
        #'mail': [byte encoded mail]
        #'uid': [byte encode uid]
        #'objectclass':[byte encode list]
        #'userpassword': hashed
        #'some other oid passwords':hashed
        #}
        #)]

        results = con.search_s(ldap_base, ldap.SCOPE_SUBTREE,filter,attr)
        #exit with 400 if user doesn't exists
        if len(results) == 0:
          return Response(
          mimetype="application/json",
          response=json.dumps("User doesn't exists") ,
          status=404
        )

        rDict = results[0][1]
        rDictDecoded = {i:j[0].decode('utf-8') for i,j in rDict.items()}
        #rDictDecoded.update({'dn':results[0][0]})
        responseDict = rDictDecoded
        responseDict['username']= rDictDecoded.pop('cn')
        responseDict['firstname']= rDictDecoded.pop('givenname')
        responseDict['lastname']= rDictDecoded.pop('sn')
        responseDict['email']= rDictDecoded.pop('mail')
        responseDict['phone']= rDictDecoded.pop('mobile')
        #responseDict['displayName']= rDictDecoded.pop('displayName')
        responseDict['oragnization']= rDictDecoded.pop('o')
        responseDict['country']= rDictDecoded.pop('c')
        responseDict['empId']= rDictDecoded.pop('uid')
        responseDict['fullname']= rDictDecoded.pop('title')
        responseDict['platform']= rDictDecoded.pop('employeetype')
        responseDict['accountstatus']= rDictDecoded.pop('orclisenabled')
        responseDict['incidentID']= rDictDecoded.pop('l')
        responseDict['role']= rDictDecoded.pop('description')
        #responseDict['managerDomainId']= rDictDecoded.pop('managerid')
        #responseDict['managerEmailId']= rDictDecoded.pop('manageremailid')








       #name_matched=results[0][1]['cn'][0].decode('utf-8')
        if len(results) != 0:
           rValue=responseDict
           code=200
        elif len(results) == 0:
           rValue="User Not Found!"
           code=404
        resp = Response(
          mimetype="application/json",
          response=json.dumps(rValue),
          status=code
        )
        return resp

     except ldap.LDAPError as e:

        mssg = list(e.args)[0]['desc']
        rValue ="Error while searching user: " + mssg
        return Response(
          mimetype="application/json",
          response=json.dumps(rValue),
          status=400
        )




#user modify
#sample request
#curl -i -X POST http://10.21.74.44:5000/updateuser --data '{"username":"test1.testSN1","email":"newmail@test.com","phone":"1234577777"}' -H 'Content-Type: application/json'



@app.route('/updateuser', methods=['POST'])
def update():
    if request.method == 'POST':
     try:

        con.simple_bind_s(request.authorization["username"],request.authorization["password"])
        data = request.get_json()  #converting to python dictionary

        #search user to get dn
        filter = "(&(objectClass=*)(cn="+data['username']+"))"
        attr=None
        results = con.search_s(ldap_base, ldap.SCOPE_SUBTREE,filter,attr)
        if len(results) == 0:
          return Response(
          mimetype="application/json",
          response=json.dumps("User doesn't exists") ,
          status=400
        )

        dn=results[0][0]
        user_input=[i for(i,j) in data.items()] #key of all user input

        #verifying correct email format
        if('email' in user_input):

          if(everify(data['email'])==0 ):
            rValue="Incorrect email format!"
            return Response(
            mimetype="application/json",
            response=json.dumps(rValue),
            status=400)


        #verifying correct mobile number format
        if('phone' in user_input):

          if(pverify(data['phone'])==0 ):
            rValue="Incorrect mobile number format!"
            return Response(
            mimetype="application/json",
            response=json.dumps(rValue),
            status=400)

        #modifiable_attr=['phone','mCode','email']
        modifiable_attr=['phone','mCode','email','firstname','lastname','platform','organization','country','displayName','fullname','employeeId',
        'accountstatus']
        temp=[x for x in user_input if x in modifiable_attr]
        if(len(temp)==len(user_input) -1 ):  #minus 1 for username

            entry={}
            if 'phone' in user_input:
               entry['mobile']=data['phone']
            if 'email' in user_input:
               entry['mail']=data['email']

            if 'firstname' in user_input:
               entry['givenname']=data['firstname']
            if 'lastname' in user_input:
               entry['sn']=data['lastname']
            if 'platform' in user_input:
              entry['employeeType']=data['platform']
            if 'organization' in user_input:
              entry['o']=data['organization']
            if 'country' in user_input:
              entry['c']=data['country']
            if 'displayname' in user_input:
              entry['displayName']=data['displayname']
            if 'fullname' in user_input:
              entry['title']=data['fullname']
            if 'employeeId' in user_input:
              entry['uid']=data['employeeId']
            if 'accountstatus' in user_input:
              entry['orclIsEnabled']= data['accountstatus']
            if 'managerEmailId' in user_input:
                entry['manageremailid']=data['managerEmailId']

            parsed_entry=[(ldap.MOD_REPLACE,i,bytes(j,encoding='utf-8'))for i,j in entry.items()]
            con.modify_s(dn,parsed_entry)
            rValue = "Updated user : " + data['username']
            return Response(
             mimetype="application/json",
             response=json.dumps(rValue),
             status=200
               )



        else:
            rValue="Unmodifiable attributes passed in request"
            return Response(
            mimetype="application/json",
            response=json.dumps(rValue),
            status=400)




     except ldap.LDAPError as e:

        print(e)
        mssg = list(e.args)[0]['desc']
        rValue ="Error while updating user: " + mssg
        return Response(
          mimetype="application/json",
          response=json.dumps(rValue),
          status=400
        )



#password update
#sample request
#curl -i -X POST http://10.21.74.44:5000/updatepassword --data '{"username":"test1.testSN1","oldPass":"12345","newPass":"1234567"}' -H 'Content-Type: application/json'



@app.route('/updatepassword', methods=['POST'])
def updatepassword():
    if request.method == 'POST':
     try:
        con.simple_bind_s(request.authorization["username"],request.authorization["password"])
        data = request.get_json()  #converting to python dictionary
        #dn="cn="+data['fullname']+","+"cn=users,"+ldap_base

        #search user to get dn
        filter = "(&(objectClass=*)(cn="+data['username']+"))"
        attr=None
        results = con.search_s(ldap_base, ldap.SCOPE_SUBTREE,filter,attr)
        if len(results) == 0:
          return Response(
          mimetype="application/json",
          response=json.dumps("User doesn't exists") ,
          status=404
        )

        dn=results[0][0]
        con.simple_bind_s(dn, data['oldPass'])
        entry={"userPassword":data['newPass']}
        parsed_entry=[(ldap.MOD_REPLACE,i,bytes(j,encoding='utf-8'))for i,j in entry.items()]
        con.modify_s(dn,parsed_entry)
        rValue = "Updated password for user : " + data['username']
        return Response(
          mimetype="application/json",
          response=json.dumps(rValue),
          status=200
        )



     except ldap.LDAPError as e:

        mssg = list(e.args)[0]['desc']
        rValue ="Error while updating user: " + mssg
        return Response(
          mimetype="application/json",
          response=json.dumps(rValue),
          status=400
        )

#activate/deactivate user
@app.route('/activate', methods=['POST'])
def activate():
    if request.method == 'POST':
     try:
        con.simple_bind_s(request.authorization["username"],request.authorization["password"])
        data = request.get_json()  #converting to python dictionary
        #dn="cn="+data['fullname']+","+"cn=users,"+ldap_base

        #search user to get dn
        filter = "(&(objectClass=*)(cn="+data['username']+"))"
        attr=None
        results = con.search_s(ldap_base, ldap.SCOPE_SUBTREE,filter,attr)
        if len(results) == 0:
          return Response(
          mimetype="application/json",
          response=json.dumps("User doesn't exists") ,
          status=404
        )

        dn=results[0][0]
        entry={"orclIsEnabled":data['accountgstatus']}
        parsed_entry=[(ldap.MOD_REPLACE,i,bytes(j,encoding='utf-8'))for i,j in entry.items()]
        con.modify_s(dn,parsed_entry)
        rValue = "Status for user " + data['username'] + " changed to " + data["accountstatus"]
        return Response(
          mimetype="application/json",
          response=json.dumps(rValue),
          status=200
        )



     except ldap.LDAPError as e:

        mssg = list(e.args)[0]['desc']
        rValue ="Error while activating/deactivating user: " + mssg
        return Response(
          mimetype="application/json",
          response=json.dumps(rValue),
          status=400
        )

@app.route('/listuser', methods=['GET'])
def listuser():
    if request.method =='GET':
     try:
        con.simple_bind_s(request.authorization["username"],request.authorization["password"])
        role =request.args.get('role',"")
        filter = "(&(objectClass=*)(cn=*))"
        attr =['cn','orclisenabled','employeeType','description']
        search_base="ou="+role +",cn=users,"+ ldap_base
        results = con.search_s(search_base, ldap.SCOPE_SUBTREE,filter,attr)
        if len(results) == 0:
          return Response(
          mimetype="application/json",
          response=json.dumps("Role doesn't exists") ,
          status=404
        )


        length=len(results)
        responseDict={}
        for x in range(length):
          rDict = results[x][1]
          rDictDecoded = {i:j[0].decode('utf-8') for i,j in rDict.items()}
          rTemp=rDictDecoded
          rTemp['username']= rDictDecoded.pop('cn')
          rTemp['role']= rDictDecoded.pop('description')
          rTemp['platform']= rDictDecoded.pop('employeetype')
          rTemp['accountstatus']= rDictDecoded.pop('orclisenabled')
          responseDict[x+1]=rTemp
        if len(results) != 0:
           rValue=responseDict
           code=200
        elif len(results) == 0:
           rValue="Role Not Found!"
           code=404
        resp = Response(
          mimetype="application/json",
          response=json.dumps(rValue),
          status=code
        )
        return resp

     except ldap.LDAPError as e:

        mssg = list(e.args)[0]['desc']
        rValue ="Error while searching role: " + mssg
        return Response(
          mimetype="application/json",
          response=json.dumps(rValue),
          status=400
        )



app.run(host='10.26.38.183',debug=True)

