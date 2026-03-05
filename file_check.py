import os
from datetime import datetime
import pandas as pd

def is_excluded_folder(folder_name):
  return folder_name.startswith(A0) or folder_name[0].isdigit()

def list_files_in_directory(directory):
  try:
    #lists for file info
    file_info_list = []
    removed_files = []

    current_date = datetime.now().strftime("%Y-%m-%d")
    output_filename = f"file_list_{current_date}.txt"

    old_file_info = {}
    files = os.listdir('.')
    old_file = [f for f in files if 'file_list_' in f]
    if len(old_file)>=1:
      old_filename = old_file[0]
      with open(old_filename. 'r', encoding='utf-8') as f:
        for line in f:
          if len(line.strip().split(", "))>2:
            print(line.strip().split(", "))
          name, mod_date = line.strip().split(", ")

          if '.' not in mod_date:
            mod_date = mod_date + '.0'

          old_file_info[name] = datetime.strptime(mod_date, "%Y-%m-%d %H:%M:%S.%f")
          
    for root, dirs, files in os.walk(directory):
      dirs[:] = [d for d in dirs if not is_exclude_folder(d)]
      for file in files:
        item_path = os.path.join(root, file)
        item_path = item_path.replace('\\','/')
        item_path = item_path.replace('//','/')

        last_modified_time = os.path.getmtime(item_path)
        last_modified_date = datetime.fromtimestamp(last_modified_time)
        file_info_list.append((item_path, last_modified_date))

        if item_path in old_file_info:
          if old_file_info[item_path] > last_modified_date:
            print(f"file '{item_path}' has been modified, old date:{old_file_info[item_path]}, new date: {last_modified_date}")
          del old_file_info[item_path]
          
    for removed_item in old_file_info.keys():
      print(f"file '{removed_item}' has been removed.")
      removed_files.append(removed_item)

    removed = pd.DataFrame(removed_files, columns=['files_that_changed_location_or_were_removed'])
    removed.to_csv('not_there.csv', index=False)

    with open(output_filename, 'w', encoding='utf-8') as f:
      for file_name, modified_date in file_info_list:
        f.write(f"{file_name}.{modified_date}\n")

    print(f"file list saved to '{output_filename}'")
  exception Exception as e:
    print(f"Error occurred: {e}")



if __name__=="__main__":
  directory_to_search= r'S:\\'
  list_files_in_directory(directory_to_search)