from mongoengine import *
import datetime

# connect("mongodb+srv://saif:brick@cluster0.j6jw7.mongodb.net/?retryWrites=true&w=majority")
connect( db='wsrc_bme2', username='saif', password='brick', host='mongodb+srv://saif:brick@cluster0.j6jw7.mongodb.net')


def mobile_val(val):
  pass





class Permission(Document):
    name = StringField(unique=True, min_length=1,  max_length=100, required=True) 

class Role(Document):
    name  = StringField(unique=True, min_length=1, max_length=100, required=True)
    permission_array = ListField()


class User(Document):
  status_dict = (
                ("active", "Active"),
                ("inactive", "Inactive"),
                ("banned", "Banned"),
                ("deleted", "Deleted")
                  )

  
  name = StringField(required=True)
  username = StringField(unique=True, required=True, max_length=50)
  password = StringField(required=True)
  email = EmailField(required=True)
  mobile = IntField(required=True)
  address = StringField(required=True)
  role = ReferenceField(Role)
  status = StringField(required=True, choices=status_dict)
  created_at = DateTimeField(default=datetime.datetime.utcnow)
  updated_at = DateTimeField(default=datetime.datetime.utcnow)





