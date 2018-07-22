# Clone MyDynamoRIO Visual Studio 2015 Project with custom DynamoRIO settings
# Place this script in the same folder as the MyDynamoRIO template project and run it from there
import os
import sys
import argparse
import shutil
from distutils.dir_util import copy_tree

def update_project_name(new_project, src_project, client_name):
  directory_listing = os.listdir(new_project)
  for file in directory_listing:
    full_file_path = os.path.join(new_project, file)

    if ".vs" in full_file_path:
      os.rename(full_file_path + '\\MyDynamoRIO', full_file_path + '\\' + client_name)
      continue

    if os.path.isdir(full_file_path):
      if file == "MyDynamoRIO":
        pwd = os.getcwd()
        src = os.path.join(pwd, client_name + "\\MyDynamoRIO")
        dst = os.path.join(pwd, client_name + "\\" + client_name)
        copy_tree(src, dst)
        shutil.rmtree(src)
        update_project_name(dst, src, client_name)
        continue

    updated_name = file.replace("MyDynamoRIO", client_name)
    file_content = open(full_file_path, "rb").read()
    os.remove(os.path.join(new_project, file))
    updated_content = file_content.replace("MyDynamoRIO", client_name)
    f = open(os.path.join(new_project, updated_name), "wb")
    f.write(updated_content)
    f.close()


def clone_project(client_name):
  pwd = os.getcwd()
  src_project = os.path.join(pwd, "MyDynamoRIO")
  new_project = os.path.join(pwd, client_name)

  if(os.path.exists(new_project)):
    print "[-] DynamoRIO Project name already exists. Exiting!"
    sys.exit()

  copy_tree(src_project, new_project)
  update_project_name(new_project, src_project, client_name)


def main():	
  parser = argparse.ArgumentParser(description='Create DynamoRIO Project')
  req = parser.add_argument_group('required arguments')
  req.add_argument('-p', dest='project_name', action="store", help='DynamoRIO VS Project Name', required=True)
  args = parser.parse_args()
  
  clone_project(args.project_name)
  print "DynamoRIO Project created: %s" % args.project_name


if __name__ == '__main__':
  main()