# Clone MyPinTool Visual Studio (2015) Project
# Place this script in the $PIN_PATH/source/tools and run it from there
import os
import sys
import argparse
from distutils.dir_util import copy_tree


def update_project_name(new_project, src_project, pintool_name):
  directory_listing = os.listdir(new_project)
  for file in directory_listing:
    full_file_path = os.path.join(new_project, file)

    if ".vs" in full_file_path:
      os.rename(full_file_path + '\\MyPinTool', full_file_path + '\\' + pintool_name)
      continue

    updated_name = file.replace("MyPinTool", pintool_name)
    file_content = open(full_file_path, "rb").read()
    os.remove(os.path.join(new_project, file))
    updated_content = file_content.replace("MyPinTool", pintool_name)
    f = open(os.path.join(new_project, updated_name), "wb")
    f.write(updated_content)
    f.close()


def clone_project(pintool_name):
  pwd = os.getcwd()
  src_project = os.path.join(pwd, "MyPinTool")
  new_project = os.path.join(pwd, pintool_name)

  if(os.path.exists(new_project)):
    print "[-] Pintool Project name already exists. Exiting!"
    sys.exit()

  copy_tree(src_project, new_project)
  update_project_name(new_project, src_project, pintool_name)


def main():	
  parser = argparse.ArgumentParser(description='Create Pintool Project')
  req = parser.add_argument_group('required arguments')
  req.add_argument('-p', dest='project_name', action="store", help='Pintool VS Project Name', required=True)
  args = parser.parse_args()
  
  clone_project(args.project_name)
  print "Pintool Project created: %s" % args.project_name


if __name__ == '__main__':
  main()
