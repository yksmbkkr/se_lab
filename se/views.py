from django.http import HttpResponseRedirect
from django.shortcuts import redirect

def redirect_signin(request):
    return redirect('society:login')

def home_redirect(request):
    return redirect('society:s_list')
