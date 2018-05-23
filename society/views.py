from django.shortcuts import render, get_object_or_404, redirect
from django.template.context_processors import csrf
from .forms import *
from django.http import HttpResponse, Http404, HttpResponseRedirect
from .models import *
from django.conf import settings
from django.views.generic import UpdateView
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login
from django.contrib.auth import update_session_auth_hash
from django.contrib import messages
from .decorators import *
from .reg_no_generator import reg_no_generator
from datetime import date


# Create your views here.

#society account activity
def register(request):
    if request.user.is_authenticated():
        return HttpResponseRedirect('/')
    else:
        if request.method == 'POST':
            form = SignUpForm(request.POST)
            if form.is_valid():
                emailad = form.cleaned_data.get('email')
                if User.objects.filter(email=emailad).count() > 0 :
                     messages.error(request, 'User with the submitted email id is already registered.')
                     return redirect('society:register')
                form.save()
                username = form.cleaned_data.get('username')
                raw_password = form.cleaned_data.get('password1')
                user = authenticate(username=username, password=raw_password)
                login(request, user)
                profile_object = profile_check(user = request.user, check=False)
                profile_object.save()
                return redirect('society:create_profile')
        else:
            form = SignUpForm()
        return render(request, 'signup.html', {'form': form})

@login_required
def changepass(request):
    if request.method == 'POST':
        form = PasswordChangeCustomForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(request, 'Your password was successfully updated!')
            return redirect('society:mod_pass')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = PasswordChangeCustomForm(request.user)
    return render(request, 'changepass.html', {'form':form})

# Society profile activity

@login_required
@create_profile
def create_profile(request):
    if request.method == 'POST':
        form = society_profile_form(request.POST, request.FILES)
        if form.is_valid():
            finalform=form.save(commit=False)
            finalform.user = request.user
            profile_check.objects.filter(user = request.user).update(check = True)
            finalform.save()
            url_directory_object = url_directory(url = finalform.url_extension, society_username = request.user.username, user = request.user)
            url_directory_object.save()
            return redirect('/society/'+finalform.url_extension)
    else:
        form = society_profile_form
    return render(request,'profile.html',{'form':form})

def society_space(request, space_id):
    space_id = str(space_id)
    try:
        space = url_directory.objects.get(url = space_id)
    except url_directory.DoesNotExist :
        raise Http404("No such society is registered with us.")
    space_object = society_profile.objects.get(user = space.user)
    arg = {'soc':space_object,}
    return render(request, 'view_profile.html', arg)

def list_society(request):
    category = request.GET.get('ctg')
    if category == None:
        s_list = society_profile.objects.all()
    else:
        try:
            s_list = society_profile.objects.filter(category = category)
            if society_profile.objects.filter(category = category).count()==0:
                raise Http404("Invalid Parameter")
        except society_profile.DoesNotExist :
            raise Http404("Invalid Parameter")
    return render(request, 'list_society.html',{'list':s_list})

@login_required
@is_profile_created
def edit_profile(request):
    if request.method == 'POST':
        form = society_profile_form(request.POST, request.FILES, instance = society_profile.objects.get(user = request.user))
        if form.is_valid():
            
            form.save()
            u_ex = society_profile.objects.get(user = request.user).url_extension
            return HttpResponseRedirect('/society/'+u_ex)
    else:
        form = society_profile_form(instance = society_profile.objects.get(user = request.user))
    return render(request,'profile.html',{'form':form})

@login_required
@is_profile_created
def create_event(request):
    if request.method=='POST':
        form = event_form(request.POST)
        if form.is_valid():
            finalform = form.save(commit = False)
            finalform.user = request.user
            event_id = reg_no_generator()
            finalform.event_id = event_id
            finalform.save()
            return redirect('society:my_events')
    else:
        form = event_form()
    return render(request,'soc_profile.html',{'form':form})

@login_required
@is_profile_created
def edit_event(request):
    eid = request.GET.get('eid')
    try: 
        event_object = event.objects.get(event_id = eid)
    except event.DoesNotExist:
        raise Http404("Invalid Parameters")
    if event_object.user != request.user:
        raise Http404("You are not authorised to do this operation")
    if request.method == 'POST':
        form = event_form(request.POST,  instance = event.objects.get(event_id = eid))
        if form.is_valid():
            
            form.save()
           
            return redirect('society:my_events')
    else:
        form = event_form(instance = event.objects.get(event_id = eid))
    return render(request,'soc_profile.html',{'form':form})

def view_event(request):
    eid = request.GET.get('eid')
    try: 
        event_object = event.objects.get(event_id = eid)
    except event.DoesNotExist:
        raise Http404("Invalid Parameters")
    society_object = society_profile.objects.get(user = event_object.user)
    arg = {'e':event_object,'s':society_object}
    return render(request, 'view_event.html', arg)

def list_event(request):
    event_set = event.objects.all()
    list = []
    for obj in event_set:
        e = obj
        s = society_profile.objects.get(user = obj.user)
        data_dict = {'e':e, 's':s}
        list.append(data_dict)
    return render(request, 'list_event.html', {'list':list})


@login_required
@is_profile_created
def my_events(request):
    past_e = []
    live_e = []
    e_list = event.objects.filter(user = request.user)
    for e in e_list:
        if date.today() > e.date:
            past_e.append(e)
        else:
            live_e.append(e)
    return render(request, 'my_event.html', {'past_e':past_e, 'live_e':live_e})

def trial(request):
    return render(request,'soc_profile.html')

