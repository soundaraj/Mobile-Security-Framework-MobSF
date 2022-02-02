# -*- coding: utf_8 -*-
"""MobSF File Upload and Home Routes."""
import json
import logging
import os
import platform
import re
import shutil
from wsgiref.util import FileWrapper

from django.conf import settings
from django.core.paginator import Paginator
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render, redirect
from django.template.defaulttags import register
from django.contrib.auth import login, authenticate,logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.sites.shortcuts import get_current_site  
from django.utils.encoding import force_bytes ,force_str 
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode  
from django.template.loader import render_to_string

from mobsf.MobSF.models import pricingModel, userPricingModel  
from .token import account_activation_token  
from django.contrib.auth.models import User  
from django.core.mail import EmailMessage  
from mobsf.MobSF.forms import FormUtil, UploadFileForm, RegistrationForm
from mobsf.MobSF.utils import (
    api_key,
    is_dir_exists,
    is_file_exists,
    is_safe_path,
    print_n_send_error_response,
)
from mobsf.MobSF.views.helpers import FileType
from mobsf.MobSF.views.scanning import Scanning
from mobsf.MobSF.views.apk_downloader import apk_download
from mobsf.StaticAnalyzer.models import (
    RecentScansDB,
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS,
    StaticAnalyzerWindows,
)

LINUX_PLATFORM = ['Darwin', 'Linux']
HTTP_BAD_REQUEST = 400
logger = logging.getLogger(__name__)


@register.filter
def key(d, key_name):
    """To get dict element by key name in template."""
    return d.get(key_name)

@login_required(login_url='login')
def index(request):
    try:
        plan = request.user.plan
        if(plan.scan_count < plan.plan.scan_limit ):

            """Index Route."""
            mimes = (settings.APK_MIME
                    + settings.IPA_MIME
                    + settings.ZIP_MIME
                    + settings.APPX_MIME)
            context = {
                'version': settings.MOBSF_VER,
                'mimes': mimes,
            }
            template = 'general/home.html'
            return render(request, template, context)
        else:
            plans = pricingModel.objects.all()
            return render(request,'pricing.html',{"message":"please upgrade your plan","plans":plans})
    except:
        return redirect('pricing')


class Upload(object):
    """Handle File Upload based on App type."""

    def __init__(self, request):
        self.request = request
        self.form = UploadFileForm(request.POST, request.FILES)
        self.file_type = None
        self.file = None

    @staticmethod
    def as_view(request):
        upload = Upload(request)
        return upload.upload_html()

    def resp_json(self, data):
        resp = HttpResponse(json.dumps(data),
                            content_type='application/json; charset=utf-8')
        resp['Access-Control-Allow-Origin'] = '*'
        return resp

    def upload_html(self):
        request = self.request
        response_data = {
            'description': '',
            'status': 'error',
        }
        if request.method != 'POST':
            msg = 'Method not Supported!'
            logger.error(msg)
            response_data['description'] = msg
            return self.resp_json(response_data)

        if not self.form.is_valid():
            msg = 'Invalid Form Data!'
            logger.error(msg)
            response_data['description'] = msg
            return self.resp_json(response_data)

        self.file = request.FILES['file']
        self.file_type = FileType(self.file)
        if not self.file_type.is_allow_file():
            msg = 'File format not Supported!'
            logger.error(msg)
            response_data['description'] = msg
            return self.resp_json(response_data)

        if self.file_type.is_ipa():
            if platform.system() not in LINUX_PLATFORM:
                msg = 'Static Analysis of iOS IPA requires Mac or Linux'
                logger.error(msg)
                response_data['description'] = msg
                return self.resp_json(response_data)

        response_data = self.upload()
        return self.resp_json(response_data)

    def upload_api(self):
        """API File Upload."""
        api_response = {}
        request = self.request
        if not self.form.is_valid():
            api_response['error'] = FormUtil.errors_message(self.form)
            return api_response, HTTP_BAD_REQUEST
        self.file = request.FILES['file']
        self.file_type = FileType(self.file)
        if not self.file_type.is_allow_file():
            api_response['error'] = 'File format not Supported!'
            return api_response, HTTP_BAD_REQUEST
        api_response = self.upload()
        return api_response, 200

    def upload(self):
        request = self.request
        scanning = Scanning(request)
        content_type = self.file.content_type
        file_name = self.file.name
        plan = request.user.plan
        plan.scan_count = int(plan.scan_count) + 1
        plan.save()
        logger.info('MIME Type: %s FILE: %s', content_type, file_name)
        if self.file_type.is_apk():
            return scanning.scan_apk()
        elif self.file_type.is_xapk():
            return scanning.scan_xapk()
        elif self.file_type.is_apks():
            return scanning.scan_apks()
        elif self.file_type.is_zip():
            return scanning.scan_zip()
        elif self.file_type.is_ipa():
            return scanning.scan_ipa()
        elif self.file_type.is_appx():
            return scanning.scan_appx()


def api_docs(request):
    """Api Docs Route."""
    context = {
        'title': 'REST API Docs',
        'api_key': api_key(),
        'version': settings.MOBSF_VER,
    }
    template = 'general/apidocs.html'
    return render(request, template, context)


def about(request):
    """About Route."""
    context = {
        'title': 'About',
        'version': settings.MOBSF_VER,
    }
    template = 'general/about.html'
    return render(request, template, context)

from email.mime.text import MIMEText
import smtplib
smtp_ssl_host = "mail.cyberheals.com"
smpt_ssl_port = 465
usr_name= "noreply@cyberheals.com"
pwd = "noreply@123"
sende = 'Cyber Heals<noreply@cyberheals.com>'
def register(request):
    """Register Route."""
    context = {}
    if request.POST:
        form = RegistrationForm(request.POST)
        if form.is_valid():
            # form.save()
            user = form.save(commit=False)  
            user.is_active = False  
            user.save()  
            email = form.cleaned_data.get('email')
            raw_password = form.cleaned_data.get('password1')
            # account = authenticate(email = email, password = raw_password)
            # login(request, account)
            # return redirect('home')
            current_site = get_current_site(request)  
            mail_subject = 'Activation link has been sent to your email id'  
            message = render_to_string('acc_active_email.html', {  
                'user': user,  
                'domain': current_site.domain,  
                'uid':urlsafe_base64_encode(force_bytes(user.pk)),  
                'token':account_activation_token.make_token(user),  
            })  
            to_email = form.cleaned_data.get('email')  
            # email = EmailMessage(  
            #             mail_subject, message, to=[to_email]  
            # )  
            # email.send()  
            message = MIMEText(message,'html')
            message['Subject'] = mail_subject
            message['From'] = sende
            message['To'] = "user" + "<"+to_email+">"
            server = smtplib.SMTP_SSL(smtp_ssl_host,smpt_ssl_port)
            server.login(usr_name,pwd)
            print(server,message)
            server.sendmail(sende,[to_email] ,message.as_string())
            return HttpResponse('Please confirm your email address to complete the registration')
        else:
            context = {
                'title': 'Register',
                'version': settings.MOBSF_VER,
                'registration_form': form
            }
            template = 'general/register.html'
            return render(request, template, context)
    else: #GET request
        form = RegistrationForm()
        context = {
            'title': 'Register',
            'version': settings.MOBSF_VER,
            'registration_form': form
        }
    template = 'general/register.html'
    return render(request, template, context)
from django.contrib.auth import get_user_model
def activate(request, uidb64, token):  
    User = get_user_model()  
    try:  
        uid = force_str(urlsafe_base64_decode(uidb64))  
        user = User.objects.get(pk=uid)  
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):  
        user = None  
    if user is not None and account_activation_token.check_token(user, token):  
        user.is_active = True  
        user.save() 
        login(request, user) 
        return redirect('pricing')
    else:  
        return HttpResponse('Activation link is invalid!')  
def loginView(request):
    """Login Route."""
    context = {}
    if request.POST:
        email = request.POST['email']
        password = request.POST['password']
        if((email != None) and (password != None)):
            user  = authenticate(email = email, password = password)
            print("email++++", email)
            print("password++++", password)
            print("account++++", user )
            if user is not None:
                login(request, user)
                # Redirect to a success page.
                return redirect('home')
                ...
            else:
                # Return an 'invalid login' error message.
                return redirect('login')
            
        else:
            context = {
                'title': 'Login',
                'version': settings.MOBSF_VER,
                'login_form': form
            }
            template = 'general/login.html'
            return render(request, template, context)
    else: #GET request
        form = AuthenticationForm()
        context = {
            'title': 'Login',
            'version': settings.MOBSF_VER,
            'login_form': form
        }
    template = 'general/login.html'
    return render(request, template, context)
def logout_view(request):
    logout(request)
    return redirect('login')
def pricingPage(request):
    plan_id = 0
    plans = pricingModel.objects.all()
    if(request.user):
        try:
            if(request.user.plan):
                plan_id = request.user.plan.id
        except:
            pass
    return render(request,'pricing.html',{"plan_id":plan_id,"plans":plans})
import razorpay
client = razorpay.Client(auth=("rzp_test_hN9vjoVyq1DwUd", "GQ6GLqPMPQANvtB6AiShPgbH"))
def activatePlan(request,pk):
    context = {}
    pricingPlan = pricingModel.objects.get(id=pk)
    if(request.user.is_authenticated):
        userPlan = userPricingModel.objects.filter(user=request.user)
        if(userPlan.count() != 0 ):
            userPlan = userPricingModel.objects.get(user=request.user)
            if(userPlan.plan.id == pricingPlan.id):
                pass
            else:
                if(int(pk) == 2):
                    print("pk",2)
                    order_amount = int(pricingPlan.price) * 100
                    order_currency = 'INR'
                    order_receipt = 'order_rcptid_11'
                    notes = {
                        'Shipping address': 'Bommanahalli, Bangalore'}

                    # CREAING ORDER
                    response = client.order.create(dict(amount=order_amount, currency=order_currency, receipt=order_receipt, notes=notes, payment_capture='0'))
                    order_id = response['id']
                    order_status = response['status']
                    print(response)
                    if order_status=='created':

                        # Server data for user convinience
                        context['product_id'] = pk
                        context['price'] = order_amount
                        context['name'] = request.user.username
                        context['phone'] = "phone"
                        context['email'] = "email"

                        # data that'll be send to the razorpay for
                        context['order_id'] = order_id

                        userPlan.plan = pricingPlan
                        userPlan.save()
                        return render(request, 'confirm_order.html', context)
                    else:
                        return HttpResponse("Order not created")
                else:
                    userPlan.plan = pricingPlan
                    userPlan.save()
                    return redirect("home")
        else:
            userPlan = userPricingModel.objects.create(user=request.user,plan=pricingPlan)
            userPlan.scan_count = 0
            userPlan.save()
            if(int(pk) == 2):
                order_amount = int(pricingPlan.price) * 100
                order_currency = 'INR'
                order_receipt = 'order_rcptid_11'
                notes = {
                    'Shipping address': 'Bommanahalli, Bangalore'}

                # CREAING ORDER
                response = client.order.create(dict(amount=order_amount, currency=order_currency, receipt=order_receipt, notes=notes, payment_capture='0'))
                order_id = response['id']
                order_status = response['status']

                if order_status=='created':

                    # Server data for user convinience
                    context['product_id'] = pk
                    context['price'] = order_amount
                    context['name'] = request.user.username
                    context['phone'] = "phone"
                    context['email'] = "email"

                    # data that'll be send to the razorpay for
                    context['order_id'] = order_id

                    return render(request, 'confirm_order.html', context)
        return redirect("home")
    else:
        return redirect("register")
# def activatePlan(request,pk):
#     context = {}
#     if request.method == 'POST':
#         if(int(pk) == 2):
#             print("INSIDE Create Order!!!")
            

#             order_amount = 10000
            

#             order_currency = 'INR'
#             order_receipt = 'order_rcptid_11'
#             notes = {
#                 'Shipping address': 'Bommanahalli, Bangalore'}

#             # CREAING ORDER
#             response = client.order.create(dict(amount=order_amount, currency=order_currency, receipt=order_receipt, notes=notes, payment_capture='0'))
#             order_id = response['id']
#             order_status = response['status']

#             if order_status=='created':

#                 # Server data for user convinience
#                 context['product_id'] = "product"
#                 context['price'] = order_amount
#                 context['name'] = "name"
#                 context['phone'] = "phone"
#                 context['email'] = "email"

#                 # data that'll be send to the razorpay for
#                 context['order_id'] = order_id


#                 return render(request, 'confirm_order.html', context)
#         else:
#             return redirect("home")

#         # print('\n\n\nresponse: ',response, type(response))
#     return HttpResponse('<h1>Error in  create order function</h1>')
from django.views.decorators.csrf import csrf_exempt
@csrf_exempt
def payment_status(request):

    response = request.POST
    print(response)

    params_dict = {
        'razorpay_payment_id' : response['razorpay_payment_id'],
        'razorpay_order_id' : response['razorpay_order_id'],
        'razorpay_signature' : response['razorpay_signature']
    }


    # VERIFYING SIGNATURE
    try:
        status = client.utility.verify_payment_signature(params_dict)
        return redirect('home')
    except:
        return HttpResponse('Payment Faliure!!!')
def error(request):
    """Error Route."""
    context = {
        'title': 'Error',
        'version': settings.MOBSF_VER,
    }
    template = 'general/error.html'
    return render(request, template, context)


def zip_format(request):
    """Zip Format Message Route."""
    context = {
        'title': 'Zipped Source Instruction',
        'version': settings.MOBSF_VER,
    }
    template = 'general/zip.html'
    return render(request, template, context)


def not_found(request):
    """Not Found Route."""
    context = {
        'title': 'Not Found',
        'version': settings.MOBSF_VER,
    }
    template = 'general/not_found.html'
    return render(request, template, context)


def recent_scans(request):
    """Show Recent Scans Route."""
    entries = []
    db_obj = RecentScansDB.objects.all().order_by('-TIMESTAMP').values()
    android = StaticAnalyzerAndroid.objects.all()
    package_mapping = {}
    for item in android:
        package_mapping[item.MD5] = item.PACKAGE_NAME
    for entry in db_obj:
        if entry['MD5'] in package_mapping.keys():
            entry['PACKAGE'] = package_mapping[entry['MD5']]
        else:
            entry['PACKAGE'] = ''
        entries.append(entry)
    context = {
        'title': 'Recent Scans',
        'entries': entries,
        'version': settings.MOBSF_VER,
    }
    template = 'general/recent.html'
    return render(request, template, context)


def download_apk(request):
    """Download and APK by package name."""
    package = request.POST['package']
    # Package validated in apk_download()
    context = {
        'status': 'failed',
        'description': 'Unable to download APK',
    }
    res = apk_download(package)
    if res:
        context = res
        context['status'] = 'ok'
        context['package'] = package
    resp = HttpResponse(
        json.dumps(context),
        content_type='application/json; charset=utf-8')
    return resp


def search(request):
    """Search Scan by MD5 Route."""
    md5 = request.GET['md5']
    if re.match('[0-9a-f]{32}', md5):
        db_obj = RecentScansDB.objects.filter(MD5=md5)
        if db_obj.exists():
            e = db_obj[0]
            url = (f'/{e.ANALYZER }/?name={e.FILE_NAME}&'
                   f'checksum={e.MD5}&type={e.SCAN_TYPE}')
            return HttpResponseRedirect(url)
        else:
            return HttpResponseRedirect('/not_found/')
    return print_n_send_error_response(request, 'Invalid Scan Hash')


def download(request):
    """Download from mobsf.MobSF Route."""
    if request.method == 'GET':
        root = settings.DWD_DIR
        allowed_exts = settings.ALLOWED_EXTENSIONS
        filename = request.path.replace('/download/', '', 1)
        dwd_file = os.path.join(root, filename)
        # Security Checks
        if '../' in filename or not is_safe_path(root, dwd_file):
            msg = 'Path Traversal Attack Detected'
            return print_n_send_error_response(request, msg)
        ext = os.path.splitext(filename)[1]
        if ext in allowed_exts:
            if os.path.isfile(dwd_file):
                wrapper = FileWrapper(
                    open(dwd_file, 'rb'))  # lgtm [py/path-injection]
                response = HttpResponse(
                    wrapper, content_type=allowed_exts[ext])
                response['Content-Length'] = os.path.getsize(dwd_file)
                return response
        if filename.endswith(('screen/screen.png', '-icon.png')):
            return HttpResponse('')
    return HttpResponse(status=404)


def delete_scan(request, api=False):
    """Delete Scan from DB and remove the scan related files."""
    try:
        if request.method == 'POST':
            if api:
                md5_hash = request.POST['hash']
            else:
                md5_hash = request.POST['md5']
            data = {'deleted': 'scan hash not found'}
            if re.match('[0-9a-f]{32}', md5_hash):
                # Delete DB Entries
                scan = RecentScansDB.objects.filter(MD5=md5_hash)
                if scan.exists():
                    RecentScansDB.objects.filter(MD5=md5_hash).delete()
                    StaticAnalyzerAndroid.objects.filter(MD5=md5_hash).delete()
                    StaticAnalyzerIOS.objects.filter(MD5=md5_hash).delete()
                    StaticAnalyzerWindows.objects.filter(MD5=md5_hash).delete()
                    # Delete Upload Dir Contents
                    app_upload_dir = os.path.join(settings.UPLD_DIR, md5_hash)
                    if is_dir_exists(app_upload_dir):
                        shutil.rmtree(app_upload_dir)
                    # Delete Download Dir Contents
                    dw_dir = settings.DWD_DIR
                    for item in os.listdir(dw_dir):
                        item_path = os.path.join(dw_dir, item)
                        valid_item = item.startswith(md5_hash + '-')
                        # Delete all related files
                        if is_file_exists(item_path) and valid_item:
                            os.remove(item_path)
                        # Delete related directories
                        if is_dir_exists(item_path) and valid_item:
                            shutil.rmtree(item_path)
                    data = {'deleted': 'yes'}
            if api:
                return data
            else:
                ctype = 'application/json; charset=utf-8'
                return HttpResponse(json.dumps(data), content_type=ctype)
    except Exception as exp:
        msg = str(exp)
        exp_doc = exp.__doc__
        if api:
            return print_n_send_error_response(request, msg, True, exp_doc)
        else:
            return print_n_send_error_response(request, msg, False, exp_doc)


class RecentScans(object):

    def __init__(self, request):
        self.request = request

    def recent_scans(self):
        page = self.request.GET.get('page', 1)
        page_size = self.request.GET.get('page_size', 10)
        result = RecentScansDB.objects.all().values().order_by('-TIMESTAMP')
        try:
            paginator = Paginator(result, page_size)
            content = paginator.page(page)
            data = {
                'content': list(content),
                'count': paginator.count,
                'num_pages': paginator.num_pages,
            }
        except Exception as exp:
            data = {'error': str(exp)}
        return data
