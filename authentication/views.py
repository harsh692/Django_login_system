from django.contrib.auth import authenticate, login, logout
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail, EmailMessage
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes , force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode


from LoginSystem import settings
from .tokens import generate_token


def home(request):
    return render(request,"authentication/index.html")

def signup(request):

    if request.method == "POST":
        username = request.POST['username']
        fname = request.POST['fname']
        lname = request.POST['lname']
        email = request.POST['email']
        pass1 = request.POST['pass1']
        pass2 = request.POST['pass2']

        if User.objects.filter(username = username):
            messages.error(request,"Username already exist! Please try some other username")
            return redirect("home")

        if User.objects.filter(email=email).exists():
            messages.error(request,"Email already exist!")
            return redirect('home')

        if len(username)>20:
            messages.error(request,'username must be under 20 characters')
            return redirect('home')

        if pass1 != pass2:
            messages.error(request,'passwords didnt match!')
            return redirect('home')

        if not username.isalnum():
            messages.error(request,"username must be alpha-numeric!")
            return redirect('home')


        myuser = User.objects.create_user(username,email,pass1)
        myuser.first_name= fname
        myuser.last_name = lname
        myuser.is_active = False ## return later for email authentication.
        myuser.save()

        messages.success(request,"Your account has been successfully created! We have sent you a confirmation email ,please confirm your"
                                 "email to confirm it.")

        # welcome email

        subject = 'Welcome to LoginSystem'
        message =  "Hello"+myuser.first_name+'!! \n' +"Welcome to LoginSystems !! \n Thank you for visiting our site and creating a id. \n KLEIN"
        from_email = settings.EMAIL_HOST_USER
        to_list = [myuser.email]
        send_mail(subject,message,from_email,to_list,fail_silently=True)

        # confirmation email

        current_site = get_current_site(request)
        email_subject = "confirm your email at django login system"
        message2 = render_to_string("email_confirmation.html",{
            'name' : myuser.first_name,
            'domain' : current_site.domain,
            'uid' : urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token' : generate_token.make_token(myuser)
        })
        email = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [myuser.email],
        )

        email.fail_silently = True
        email.send()


        return redirect('signin')

    return render(request,"authentication/signup.html")

def signin(request):

    if request.method == "POST":
        username = request.POST['username']
        pass1 = request.POST['pass1']

        user = authenticate(username=username,password = pass1)

        print(username)
        print(pass1)
        print(user)



        if user is not None:
            login(request,user)
            fname = user.first_name
            return render(request,'authentication/index.html',{'fname': fname})
        else:
            messages.error(request,"Bad Credentials {}".format(user))
            return redirect('home')

    return render(request,"authentication/signin.html")

def signout(request):
    logout(request)
    messages.success(request,"logged out successfully")
    return redirect("home")

def activate(request,uidb64,token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except (TypeError,ValueError,OverflowError,User.DoesNotExist) as e:
        print(e)
        myuser = None

    if myuser is not None and generate_token.check_token(myuser,token):
        myuser.is_activate = True
        myuser.save()
        login(request,myuser)
        messages.success(request,'Your account has been activated!')
        return redirect('signin')
    else:
        return render(request,'activation_failed.html')


# Create your views here.
