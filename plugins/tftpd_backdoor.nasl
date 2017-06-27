# 
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(18263);
 script_version ("$Revision: 1.18 $");
 script_cvs_date("$Date: 2013/01/25 01:19:10 $");
 
 script_name(english: "TFTP Backdoor Detection");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is compromised." );
 script_set_attribute(attribute:"description", value:
"A TFTP server is running on this port.  However, while trying to fetch
a random file, we got an executable file. 

Many worms are known to propagate through TFTP.  This is probably a
backdoor." );
 script_set_attribute(attribute:"solution", value:
"Disinfect / reinstall your system." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/16");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english: "Retrieve an executable file through TFTP");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
 script_family(english: "Backdoors");
 script_dependencies('tftpd_dir_trav.nasl');
 script_require_keys("Services/udp/tftp");
 exit(0);
}

#

include('global_settings.inc');
include('misc_func.inc');
include('tftp.inc');

#

function test_exe(port, fname, fcontent)
{
  local_var mz;

  mz = substr(fcontent, 0, 1);
## MS format
  if (mz == 'MZ' || mz == 'ZM')
    if ('\x50\x45\x00\x00' >< fcontent)
      report_tftp_backdoor(port: port, file: fname, type: 'MS PE', data: fcontent);
    else
      report_tftp_backdoor(port: port, file: fname, type: 'MS', data: fcontent);
## Linux a.out
# else if (mz == '\x01\x07')	# object file or impure executable
#   report_tftp_backdoor(port: port, file: fname, type: 'a.out OMAGIC');
  else if (mz == '\x01\x08')	# pure executable
    report_tftp_backdoor(port: port, file: fname, type: 'a.out NMAGIC');
  else if (mz == '\x01\x0B')	# demand-paged executable
    report_tftp_backdoor(port: port, file: fname, type: 'a.out ZMAGIC');
  else if (mz == 'CC')	# demand-paged executable with the header in the text
    report_tftp_backdoor(port: port, file: fname, type: 'a.out QMAGIC', data:fcontent);
# else if (mz == '\x01\x11')	# core file
#   report_tftp_backdoor(port: port, file: fname, type: 'a.out CMAGIC');
## AIX a.out - is this wise?
  else if (mz == '\x01\xDF')
    report_tftp_backdoor(port: port, file: fname, type: 'XCOFF32', data: fcontent);
  else if (mz == '\x01\xEF')
    report_tftp_backdoor(port: port, file: fname, type: 'XCOFF64', data: fcontent);
## ELF
  else if (substr(fcontent, 0, 3) == '\x7fELF')
    report_tftp_backdoor(port: port, file: fname, type: 'ELF', data: fcontent);
}

port = get_kb_item('Services/udp/tftp');
if (! port) port = 69;
nb = 0;

for (i = 0; i < 1000; i ++)	# <1000 in case somebody gets mad
{
  fname = get_kb_item('tftp/'+port+'/filename/'+i);
  debug_print('tftp/'+port+'/filename/'+i, '=', fname, '\n');
  if (! fname) break;
  fcontent = get_kb_item('tftp/'+port+'/filecontent/'+i);
  debug_print('tftp/'+port+'/filecontent/'+i, '=', fcontent, '\n');
  if (! fcontent) break;
  test_exe(port: port, fname: fname, fcontent: fcontent);
}

# MA 2008-05-11: I suspect that we have problems with tftpd_dir_trav.nasl
if (i == 0 || thorough_tests > 0)
{
  fname = rand_str();
  fcontent = tftp_get(port: port, path: fname);
  if (! isnull(fcontent) && strlen(fcontent) > 0)
   test_exe(port: port, fname: fname, fcontent: fcontent);
}

