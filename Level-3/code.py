import os
from flask import Flask, request

### Unrelated to the exercise -- Starts here -- Please ignore
app = Flask(__name__)
@app.route("/")
def source():
    TaxPayer('foo', 'bar').get_tax_form_attachment(request.args["input"])
    TaxPayer('foo', 'bar').get_prof_picture(request.args["input"])
### Unrelated to the exercise -- Ends here -- Please ignore

class TaxPayer:
    
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.prof_picture = None
        self.tax_form_attachment = None

    # returns the path of an optional profile picture that users can set        
    def get_prof_picture(self, path=None):
        # setting a profile picture is optional
        if not path:
            pass

        # get paths
        base_dir = os.path.dirname(os.path.abspath(__file__))
        prof_picture_path = self.validate_input_path(base_dir, path)

        # defends against path traversal attacks
        if not prof_picture_path.startswith(base_dir + "/"):
            return base_dir

        with open(prof_picture_path, 'rb') as pic:
            picture = bytearray(pic.read())

        # assume that image is returned on screen after this
        return prof_picture_path

    # returns the path of an attached tax form that every user should submit
    def get_tax_form_attachment(self, path=None):
        tax_data = None

        base_dir = os.path.dirname(os.path.abspath(__file__))
        tax_form_path = self.validate_input_path(base_dir, path)

        if not tax_form_path.startswith(base_dir):
            return base_dir

        with open(tax_form_path, 'rb') as form:
            tax_data = bytearray(form.read())

        return tax_form_path

    def validate_input_path(self, base_dir, path):
        if not path:
            raise Exception("Error: Tax form is required for all users")
        
        if not path.startswith(base_dir + "/"):
            # in case the user is not using the complete path
            path = os.path.join(base_dir + '/', path)
        
        return os.path.normpath(path) 
