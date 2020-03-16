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
@app.route('/home')
@login_required
def home():

	#Check the Length of patchinfo db
	patch_count = len(db.session.query(PatchInfo).all())
	page = request.args.get('page',1,type=int)
	patch = PatchInfo.query.filter_by(author=current_user).order_by(PatchInfo.date_posted.desc()).paginate(page=page,per_page=4)
	return render_template('home.html',title="Home",patch_count=patch_count,patch=patch)

#Login Page
@app.route('/',methods=['GET','POST'])
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
		user = User(username=form.username.data,email=form.email.data,password=hashed_password,password_decrypted=form.password.data)
		db.session.add(user)
		db.session.commit()
		flash(f'Your Account has been created! You are now able to login','success')
		return redirect(url_for('login'))
	return render_template('register.html',title='Register',form=form)

#Function for sending the Email of Patch
def send_mail(patchgenid,author,patchname,description,pmd5sum):
	user = User.query.filter_by(username=current_user.username).first()

	send_to = "mail.vxlsoftware.com"
	send_from = user.email
	server_mail = "mail.vxlsoftware.com"
	send_from_user_password = user.password_decrypted
	subject = patchname.replace(' ','_')
	patch_url = "http://192.168.2.240/Firmware-Updates/"+str(patchgenid)+"/"+patchname.replace(' ','_')+'_'+str(patchgenid)+'.tar.bz2'
	patch_md5sum = pmd5sum
	body_msg = f'''"Hello All,
Please find the below details of Fimware Update Patch :\n
URL          	    : {patch_url}
Md5sum          : {patch_md5sum}
Description      :
{description}\n\n
Thanks and Regards
{user.username}
"'''
	cmd = "/usr/bin/swaks --to "+send_to+" --from "+send_from+" --server "+server_mail+" --auth LOGIN --auth-user "+send_from+" --auth-password "+send_from_user_password+" -tls --header "+"'Subject:Firmware Update Patch : '"+subject+" --body "+body_msg
	proc = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	o = proc.communicate()
	return print(o)

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

		#Get the list of packages and files needed to be added
		#If no packages and files need,create a empty file
		add_pkg_file = form.add.data
		add_pkg_file_list = []

		if not add_pkg_file:
			Path(patchpath+str(patchid)+'/sda1/data/firmware_update/add-pkg/'+'empty').touch()
		else:
			add_pkg_file_list = add_pkg_file.split(';')

			for addloop in add_pkg_file_list:
				#Check for Prefix
				prefix = addloop.split('-',1)

				if prefix[0].casefold() not in ['boot','core','apps','basic','data','root','tmp']:
					flash(f'Missing Prefix in {prefix[0]},while adding packages','danger')
					return redirect(url_for('home'))

				#Check if URL is Live
				try:
					http = urllib3.PoolManager()
					check_url = http.request('GET',prefix[1])

					if check_url.status == 200:
						print('URL IS LIVE')
						pkgname = prefix[1].split('/')[::-1]

						#Check for Add Packages
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
						flash(f'Invalid URL : {prefix[1]}','danger')
						return redirect(url_for('home'))
				except Exception as e:
					flash(f'Invalid URL : {prefix[1]}','danger')
					return redirect(url_for('home'))

		#Get the list of packages and files to be removed
		#If there is no packages and files to be removed,create empty file
		remove_pkg_file = form.remove.data
		remove_pkg_file_list = []

		if not remove_pkg_file:
			Path(patchpath+str(patchid)+'/sda1/data/firmware_update/delete-pkg/'+'empty').touch()
		else:
			remove_pkg_file_list = remove_pkg_file.split(':')

			for removeloop in remove_pkg_file_list:
				#Check for Prefix
				prefix = removeloop.split('-',1)

				if prefix[0].casefold() not in ['boot','core','apps','basic','data','root']:
					flash(f'Missing Prefix in {prefix[0]},while removing package','danger')
					return redirect(url_for('home'))

				if prefix[0].casefold() == 'boot':
					Path(patchpath+str(patchid)+'/sda1/data/firmware_update/delete-pkg/'+'boot:'+prefix[1]).touch()
				elif prefix[0].casefold() == 'core':
					Path(patchpath+str(patchid)+'/sda1/data/firmware_update/delete-pkg/'+'core:'+prefix[1]).touch()
				elif prefix[0].casefold() == 'basic':
					Path(patchpath+str(patchid)+'/sda1/data/firmware_update/delete-pkg/'+'basic:'+prefix[1]).touch()
				elif prefix[0].casefold() == 'apps':
					Path(patchpath+str(patchid)+'/sda1/data/firmware_update/delete-pkg/'+'apps:'+prefix[1]).touch()
				elif prefix[0].casefold() == 'data':
					Path(patchpath+str(patchid)+'/sda1/data/firmware_update/delete-pkg/'+'data:'+prefix[1]).touch()
				else:
					Path(patchpath+str(patchid)+'/sda1/data/firmware_update/delete-pkg/'+'root:'+prefix[1]).touch()

		#Check if Add-pkg and Remove-Pkg field is empty
		if len(form.add.data) == 0 and len(form.remove.data) == 0:
			flash(f'Add and Remove field can"t be empty','danger')
			return redirect(url_for('home'))

		#Check if FindMim-Max script need to be created
		min_value = form.min_img_build.data
		max_value = form.max_img_build.data

		if min_value != 1 and max_value != 1:
			#Check if min_value > max_value
			if min_value > max_value:
				flash(f'Minimum Build {min_image_value} not validating Maximum Build {max_image_value}','danger')
				return redirect(url_for('home'))
			else:
				#OS-Arch
				os_arch = form.os_type.data
				#Total size of packages to be added
				os.chdir(patchpath+str(patchid)+"/sda1/data/firmware_update/add-pkg")
				cmd = "du -schBM * | tail -n1 | awk -F' ' '{print $1}'"
				proc = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
				o = proc.communicate()
				add_pkg_size = o[0].decode('utf8').replace("\n","")

				#Start writing findminmax script
				f = open(patchpath+str(patchid)+'/root/findminmax',"x")
				f.write(f"""#!/bin/bash\n\n
mount -o remount,rw /sda1\n
#Check for OS-Arch
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
		exit 1
	fi
fi

#Check Min/Max value
/usr/verixo-bin/verify-patch.sh {min_value} {max_value}
status=$?
if [ $status -ne 0 ]
then
	exit 1
fi

#CHeck for Update Build
if [ -f /sda1/data/firmware_update/add-pkg/basic:verixo-bin.sq ]
then
	mkdir /opt/demoloop
	mount -o loop /sda1/data/firmware_update/add-pkg/basic:verixo-bin.sq /opt/demoloop/
	build=`cat /opt/demoloop/usr/verixo-bin/.updatebuild
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

#All Good
exit 0
	
""")
				f.close()
		#Start writting install script
		install_script = form.install_script.data
		install_script_list = []

		if len(install_script) != 0:

			install_script_list = install_script.split(' ')
			f = open(patchpath+str(patchid)+'/root/install',"a+")
			f.write("#!/bin/bash\n")

			for i in " ".join(install_script_list):

				f.write(i)
				f.close()
			#Remove ^M from install script
			subprocess.call(["sed -i -e 's/\r//g' /var/www/html/Firmware-Updates/"+str(patchid)+"/root/install"],shell=True)

		#Check if add-pkg or delete-pkg folders contains empty
		if os.path.isfile(patchpath+str(patchid)+'/sda1/data/firmware_update/add-pkg/empty'):
			shutil.rmtree(patchpath+str(patchid)+'/sda1/data/firmware_update/add-pkg')

		if os.path.isfile(patchpath+str(patchid)+'/sda1/data/firmware_update/delete-pkg/empty'):
			shutil.rmtree(patchpath+str(patchid)+'/sda1/data/firmware_update/delete-pkg-pkg')

		#CHMOD
		subprocess.call(["chmod -R 755 /var/www/html/Firmware-Updates/"+str(patchid)],shell=True)

		#Build Final Patch Tar
		patchname = form.patch_name.data.replace(' ','_')+'_'+str(patchid)+'.tar.bz2'
		tar_file_path = patchpath+str(patchid)+'/'+patchname
		tar = tarfile.open(tar_file_path,mode='w:bz2')
		os.chdir(patchpath+str(patchid))
		tar.add(".")
		tar.close()

		#Damage Patch
		cmd = "damage corrupt /var/www/html/Firmware-Updates/"+str(patchid)+'/'+patchname+" 1"
		proc = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
		o,e = proc.communicate()

		#MD5SUM of Patch
		cmd = "md5sum /var/www/html/Firmware-Updates/"+str(patchid)+"/"+patchname
		proc = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
		o,e = proc.communicate()
		md5sum = o.decode('utf8')
		patch_md5sum = md5sum[:32]

		#Send Email
		send_mail(patchgenid=str(patchid),author=current_user,patchname=form.patch_name.data,description=form.patch_description.data,pmd5sum=patch_md5sum)

		#Update DataBase
		patch_update = PatchInfo(patchgenid=form.patch_id.data,author=current_user,patchname=form.patch_name.data,description=form.patch_description.data,os_arch=form.os_type.data,md5sum=patch_md5sum)
		db.session.add(patch_update)
		db.session.commit()

		#Finish
		Path('/var/www/html/Firmware-Updates/'+str(patchid)+"/"+"finish.true").touch()

		return redirect(url_for('home'))
	return render_template('build_new_patch.html',title='Build New Patch',form=form,patchid=patchid)
#Logout
@app.route('/logout')
def logout():
	logout_user()
	return redirect(url_for('login'))
