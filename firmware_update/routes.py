from flask import render_template, url_for, flash, redirect, request, abort, session, jsonify
from firmware_update import app, db, bcrypt, login_manager
from firmware_update.forms import LoginForm, RegistrationForm, PatchForm
from firmware_update.models import User, PatchInfo
from flask_login import login_user, current_user, logout_user, login_required
import urllib3
import random
import os
import os.path
from os import path
import shutil
import pathlib
from pathlib import Path
import wget
import subprocess
import tarfile


#Home Page
@app.route('/')
@login_required
def home():
	#Check the Length of patchinfo db
	patch_count = len(db.session.query(PatchInfo).all())

	return render_template('home.html',title="Home",patch_count=patch_count)

#Login Page
@app.route('/login',methods=['GET','POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		if user and bcrypt.check_password_hash(user.password,form.password.data):
			login_user(user)
			next_page = request.args.get('next')
			return redirect(next_page) if next_page else redirect(url_for('home'))
		else:
			flash('Login Unsuccessful. Please check email or password','danger')
	return render_template('login.html',title='Login',form=form)


#Register Page
@app.route('/register',methods=['GET','POST'])
def register():
	if current_user.is_authenticated:
		return redirect(url_for('home'))

	form = RegistrationForm()
	if form.validate_on_submit():
		hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
		user = User(username=form.username.data, email=form.email.data, password=hashed_password)
		db.session.add(user)
		db.session.commit()
		flash(f'Your Account has been created! You are now able to login','success')
		return redirect(url_for('login'))
	return render_template('register.html',title='Register',form=form)

#Function Build Patch Working Directory
def patch_working_dir():
	
	#Global Variables
	global patchid, patchpath
	#Generate random Patch ID and Set Patch Path
	patchid = random.randint(1111,9999)
	patchpath = "/var/www/html/Firmware-Updates/"

	#Check if any Patch Path is empty and finish.true file is not available
	if not len(os.listdir(patchpath)) == 0:
		#Remove all the Folders which don't have finish.true files
		for f in os.listdir(patchpath):
			file = pathlib.Path(patchpath+f+"/"+"finish.true")
			if not file.exists():
				shutil.rmtree(patchpath + f)

	#Make Patch working Directory
	os.makedirs(patchpath+str(patchid))
	#Root
	os.makedirs(patchpath+str(patchid)+'/root')
	os.makedirs(patchpath+str(patchid)+'/sda1/data/firmware_update')
	#Add Packages
	os.makedirs(patchpath+str(patchid)+'/sda1/data/firmware_update/add-pkg')
	#Delete Packages
	os.makedirs(patchpath+str(patchid)+'/sda1/data/firmware_update/delete-pkg')
	#TMP folder
	os.makedirs(patchpath+str(patchid)+'/tmp')


#Build New Patch
@app.route('/build_new_patch',methods=['POST','GET'])
@login_required
def build_new_patch():
	form = PatchForm()
	patch_working_dir()
	
	if form.validate_on_submit():

		#Check if Add/Remove Package and Files field is empty
		if len(form.add.data) == 0 and len(form.remove.data) == 0:
			flash(f'Add and Remove field can"t be empty','danger')
			return redirect(url_for('home'))
		
		#Get the list of packages and files to be added
		#If there is no packages and files to added,create a empty file
		add_pkg_file = form.add.data
		add_pkg_file_list = []

		if not add_pkg_file:
			Path(patchpath+str(patchid)+'/sda1/data/firmware_update/add-pkg/'+'empty').touch()
		else:
			add_pkg_file_list = add_pkg_file.split(';')

			for addloop in add_pkg_file_list:

				#Check if Prefix is not matched
				prefix = addloop.split('-',1)

				if prefix[0].casefold() not in ['boot','core','apps','basic','data','root','tmp']:
					flash(f'Missing Prefix in {prefix[0]},while adding package','danger')
					return redirect(url_for('home'))

				#Check if the URL is Live
				try:
					http = urllib3.PoolManager()
					check_url = http.request('GET',prefix[1])

					if check_url.status == 200:
						print("URL IS LIVE and We are Downloading")
						pkgname = prefix[1].split('/')[::-1]

						#Check for Add packages
						if prefix[0].casefold() == 'boot':
							wget.download(url=prefix[1],out=patchpath+str(patchid)+'/sda1/data/firmware_update/add-pkg/boot:'+pkgname[0])
						elif prefix[0].casefold() == 'core':
							wget.download(url=prefix[1],out=patchpath+str(patchid)+'/sda1/data/firmware_update/add-pkg/core:'+pkgname[0])
						elif prefix[0].casefold() == 'basic':
							wget.download(url=prefix[1],out=patchpath+str(patchid)+'/sda1/data/firmware_update/add-pkg/basic:'+pkgname[0])
						elif prefix[0].casefold() == 'apps':
							wget.download(url=prefix[1],out=patchpath+str(patchid)+'/sda1/data/firmware_update/add-pkg/apps:'+pkgname[0])
						elif prefix[0].casefold() == 'data':
							wget.download(url=prefix[1],out=patchpath+str(patchid)+'/sda1/data/firmware_update/add-pkg/data:'+pkgname[0])
						elif prefix[0].casefold() == 'root':
							wget.download(url=prefix[1],out=patchpath+str(patchid)+'/sda1/data/firmware_update/add-pkg/root:'+pkgname[0])
						else:
							wget.download(url=prefix[1],out=patchpath+str(patchid)+'/tmp/'+pkgname[0])

					else:
						flash(f'Invalid URL :{prefix[1]}','danger')
						return redirect(url_for('home'))
				except Exception as e:
					print(str(e))
					flash(f'Invalid URL :{prefix[1]}','danger')
					return redirect(url_for('home'))
		#Get the list of packages and files to be added
		#If there is no packages and files to added,create a empty file
		remove_pkg_file = form.remove.data
		remove_pkg_file_list = []

		if not remove_pkg_file:
			Path(patchpath+str(patchid)+'/sda1/data/firmware_update/delete-pkg/'+'empty').touch()
		else:
			remove_pkg_file_list = remove_pkg_file.split(':')

			for removeloop in remove_pkg_file_list:
				#Check if Prefix is not matched
				prefix = removeloop.split('-',1)

				if prefix[0].casefold() not in ['boot','core','apps','basic','data','root','tmp']:
					flash(f'Missing Prefix in {prefix[0]},while removing package','danger')
					return redirect(url_for('home'))

				if prefix[0].casefold() == 'boot':
					Path(patchpath+str(patchid)+'/sda1/data/firmware_update/delete-pkg/'+'boot:'+prefix[1]).touch()
				elif prefix[0].casefold() == 'core':
					Path(patchpath+str(patchid)+'/sda1/data/firmware_update/delete-pkg/'+'core:'+prefix[1]).touch()
				elif prefix[0].casefold() == 'basic':
					Path(patchpath+str(patchid)+'/sda1/data/firmware_update/delete-pkg/'+'basic:'+prefix[1]).touch()
				elif prefix[0].casefold() == "apps":
					Path(patchpath+str(patchid)+'/sda1/data/firmware_update/delete-pkg/'+'apps:'+prefix[1]).touch()
				elif prefix[0].casefold() == "data":
					Path(patchpath+str(patchid)+'/sda1/data/firmware_update/delete-pkg/'+'data:'+prefix[1]).touch()
				else :
					Path(patchpath+str(patchid)+'/sda1/data/firmware_update/delete-pkg/'+'root:'+prefix[1]).touch()

		#Findminmax Script
		#Check for OS-Arch,Minimum-Maximum build,Check Update Build and Package Size

		#OS-Arch
		os_arch = form.os_type.data

		#Minimum-Max Value
		min_value = form.min_img_build.data
		max_value = form.max_img_build.data

		if min_value > max_value:
			flash(f'Minimum Build {min_image_value} not validating Maximum Build {max_image_value}','danger')
			return redirect(url_for('home'))

		#Get the total size of packages to be added
		os.chdir(patchpath+str(patchid)+"/sda1/data/firmware_update/add-pkg")
		cmd = "du -schBM * | tail -n1 | awk -F' ' '{print $1}'"
		proc = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
		o = proc.communicate()
		add_pkg_size = o[0].decode('utf8').replace("\n","")

		#Start writing findminmax script
		f = open(patchpath+str(patchid)+'/root/findminmax',"x")
		f.write(f"""#!/bin/bash\n\n
mount -o remount,rw /sda1\n
#Check for OS-ARCH
os_arch_type = `file /usr/verixo-bin/OS_Desktop`
echo $os_arch_type | grep -i "ELF 32-bit LSB executable"
status=$?

if [ $status -eq 0 ]
then
	os_arch_type=32
else
	os_arch_type=64
fi

if [ {os_arch} == "Multi-Arch" ]
then
	echo "It's a Multi-Arch Patch"
else
	if [ {os_arch} -ne "$os_arch_type" ]
	then
		exit
	fi
fi

#Check for Min/Max value
/usr/verixo-bin/verify-patch.sh {min_value} {max_value}
status=$?
if [ $status -ne 0 ]
then
	exit 1
fi

#Check for Update Build
if [ -f /sda1/data/firmware_update/add-pkg/basic:verixo-bin.sq ]
then
	mkdir /opt/demoloop
	mount -o loop /sda1/data/firmware_update/add-pkg/basic:verixo-bin.sq /opt/demoloop/
	build=`cat /opt/demoloop/usr/verixo-bin/.updatebuild`
	umount /opt/demoloop
	rm -rf /opt/demoloop

	/usr/verixo-bin/Firmwareupdate --checkupdatebuild $build
	status=$?

	if [ $status -ne 0 ]
	then
		exit 1
	fi
fi

#Available Space left for Package to be added
/usr/verixo-bin/Firmwareupdate --checksize {add_pkg_size}
status=$?

if [ $status -ne 0 ]
then
	exit 1
fi

#All Good to Go
exit 0

""")
		f.close()
		#Start writing Install script
		install_script = form.install_script.data
		install_script_list = []

		if len(install_script) != 0:
			install_script_list = install_script
			f = open(patchpath+str(patchid)+'/root/install',"a+")
			for i in install_script_list:
				f.write('#!/bin/bash\n'+i)
			f.close()		
	return render_template('build_new_patch.html',title='Build New Patch',form=form,patchid=patchid)
#Logout
@app.route('/logout')
def logout():
	logout_user()
	return redirect(url_for('login'))