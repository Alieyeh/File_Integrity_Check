# File_Integrity_Check
for checking file version revert or deletion on portal.
install node.js
to install n8n use command: npm install n8n -g

run using>
on powershell:

''' 

$env:NODES_EXCLUDE='[]'


$env:N8N_RESTRICT_FILE_ACCESS_TO="C:\...\project\file_check;C:\...\reports"


n8n start

'''

view on: http://localhost:5678
