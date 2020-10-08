from flask import Flask,request,Response,json
import ldap,jsonify
from emailverify import everify
from phoneverify import pverify
con =ldap.initialize('ldap://10.26.38.183:3060')
ldap_base = "dc=in,dc=ril,dc=com"
app = Flask(__name__)


#create user
#sample request
#curl -i -X POST http://10.21.74.44:5000/create --data '{"fullname":"test1.testSN1","firstname":"test1","lastname":"testSN1","businessUnit":"irm","description":"developer","mobile":"1234567890","mCode":"91","mail":"test1.testSN1@ril.com","password":"12345","uid":"t1"}' -H 'Content-Type: application/json'

@app.route('/create', methods=['POST'])
def create():
    if request.method == 'POST':
     try:
        
        con.simple_bind_s(request.authorization["username"],request.authorization["password"])  
        data = request.get_json()  #converting to python dictionary
        
        #exit if Business Unit doesn't exist
        buFilter = "(&(objectClass=organizationalUnit)(ou=" + data['businessUnit']+ "))"
        buAttr = None
        results = con.search_s(ldap_base, ldap.SCOPE_SUBTREE,buFilter,buAttr)

        if(len(results)==0):  #business unit doesn't exist
            return Response(
            mimetype="application/json",
            response=json.dumps("Business Unit doesn't exist ") ,
            status=400)

        user_input=[i for(i,j) in data.items()] #key of all user input

        #verifying correct email format

        if('mail' in user_input):

          #verify mail format only if it exists in body of user request 
          if(everify(data['mail'])==0 ):
            rValue="Incorrect email format!"
            return Response(
            mimetype="application/json",
            response=json.dumps(rValue),
            status=400)


        #verifying correct mobile number format

        if('mobile' in user_input):

          #verify mail format only if it exists in body of user request
          if(pverify(data['mobile'])==0 ):
            rValue="Incorrect mobile number format!"
            return Response(
            mimetype="application/json",
            response=json.dumps(rValue),
            status=400)


        #verifying mandatory inputs from user

        mandatory=["fullname","lastname","description","mobile","mCode","mail","password","businessUnit"]
        temp = [x for x in mandatory if x in user_input]
        missing_attr=set(mandatory) - set(temp)
        if(len(missing_attr)==0): #i.e all mandatory fields are present in user input request body

                #adding user data to LDAP DIT

                dn="cn=" + data['fullname'] + ",ou=" + data['businessUnit']+ ",cn=users," + ldap_base
                entry ={"cn":data['fullname'],"sn":data['lastname'],"givenName":data['firstname'],"objectClass":"inetOrgPerson","description":data['description'],"mobile":'+'+data['mCode']+data['mobile'],"mail":data['mail'],"userPassword":data['password'],"uid":data['uid']}
                parsed_entry=[(i,bytes(j,encoding='utf-8'))for i,j in entry.items()]
                con.add_s(dn,parsed_entry)
                rValue = "Created user : " + data['fullname']
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
        rValue ="Error while adding user: " + mssg
        return Response(
          mimetype="application/json",
          response=json.dumps(rValue),
          status=400
        )



#delete user
#sample curl
#curl -i -X POST http://10.21.74.44:5000/delete --data '{"fullname":"test1.testSN1"}' -H 'Content-Type: application/json'

@app.route('/delete', methods=['POST'])
def delete():
    if request.method == 'POST':

     try:
       
        con.simple_bind_s(request.authorization["username"],request.authorization["password"])
        data = request.get_json()  #converting to python dictionary

        #search user to get dn
        filter = "(&(objectClass=*)(cn="+data['fullname']+"))"
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
        rValue= "Deleted user : " + data['fullname']
        return Response(
          mimetype="application/json",
          response=json.dumps(rValue),
          status=204
        )


     except ldap.LDAPError as e:

        mssg = list(e.args)[0]['desc']
        rValue= "Error while deleting user " + "'"+ data['fullname'] + "': " + mssg
        return Response(
          mimetype="application/json",
          response=json.dumps(rValue),
          status=400
        )


#User search
#sample curl
#curl -i -X GET http://10.21.74.44:5000/search?fullname=test8.testSN8 -H 'Content-Type: application/json'

@app.route('/search', methods=['GET'])
def search():
    if request.method =='GET':
     try:
        con.simple_bind_s(request.authorization["username"],request.authorization["password"])
        fullname =request.args.get('fullname',"")
        filter = "(&(objectClass=*)(cn="+fullname+"))"
        #attr = None #to list all attribute in that DIT entry
        attr =['cn','sn','givenName','mail','mobile','uid']

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
        rDictDecoded.update({'dn':results[0][0]})
        responseDict = rDictDecoded
        responseDict['fullname']= rDictDecoded.pop('cn')
        responseDict['firstname']= rDictDecoded.pop('givenname')
        responseDict['lastname']= rDictDecoded.pop('sn')


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
#curl -i -X POST http://10.21.74.44:5000/updateuser --data '{"fullname":"test1.testSN1","description":"developerMOD","mobile":"1234577777"}' -H 'Content-Type: application/json'



@app.route('/updateuser', methods=['POST'])
def update():
    if request.method == 'POST':
     try:
        
        con.simple_bind_s(request.authorization["username"],request.authorization["password"])
        data = request.get_json()  #converting to python dictionary
        
        #search user to get dn
        filter = "(&(objectClass=*)(cn="+data['fullname']+"))"
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
        if('mail' in user_input):

          if(everify(data['mail'])==0 ):
            rValue="Incorrect email format!"
            return Response(
            mimetype="application/json",
            response=json.dumps(rValue),
            status=400)


        #verifying correct mobile number format
        if('mobile' in user_input):

          if(pverify(data['mobile'])==0 ):
            rValue="Incorrect mobile number format!"
            return Response(
            mimetype="application/json",
            response=json.dumps(rValue),
            status=400)

        modifiable_attr=['description','mobile','mCode','mail']
        temp=[x for x in user_input if x in modifiable_attr]
        if(len(temp)==len(user_input) -1 ):  #minus 1 for fullname
            
            entry={}					 
            if 'description' in user_input: 
               entry['description']=data['description'] 
            if 'mobile' in user_input:
               entry['mobile']=data['mobile']
            if 'mCode' in user_input:
               entry['mail']=data['mail']
            if 'mail' in user_input:
               entry['mail']=data['mail']
  
            parsed_entry=[(ldap.MOD_REPLACE,i,bytes(j,encoding='utf-8'))for i,j in entry.items()]
            con.modify_s(dn,parsed_entry)
            rValue = "Updated user : " + data['fullname']
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

        mssg = list(e.args)[0]['desc']
        rValue ="Error while updating user: " + mssg
        return Response(
          mimetype="application/json",
          response=json.dumps(rValue),
          status=400
        )



#password update
#sample request
#curl -i -X POST http://10.21.74.44:5000/updatepassword --data '{"fullname":"test1.testSN1","oldPass":"12345","newPass":"1234567"}' -H 'Content-Type: application/json'



@app.route('/updatepassword', methods=['POST'])
def updatepassword():
    if request.method == 'POST':
     try:
        con.simple_bind_s(request.authorization["username"],request.authorization["password"])
        data = request.get_json()  #converting to python dictionary
        #dn="cn="+data['fullname']+","+"cn=users,"+ldap_base

        #search user to get dn
        filter = "(&(objectClass=*)(cn="+data['fullname']+"))"
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
        rValue = "Updated password for user : " + data['fullname']
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
   


app.run(host='10.26.38.183',debug=True)

