#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10756);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2016/12/07 21:18:29 $"); 

 script_cve_id("CVE-2001-1446");
 script_bugtraq_id(3316, 3325);
 script_osvdb_id(644, 6694);
 script_xref(name:"CERT", value:"177243");

 script_name(english:"Apple Mac OS X Find-By-Content .DS_Store Web Directory Listing");
 script_summary(english:"Reads /.DS_Store or /.FBCIndex");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to get the list of files present in the remote directory.");
 script_set_attribute(attribute:"description", value:
"It is possible to read a '.DS_Store' file on the remote web server. 

This file is created by MacOS X Finder; it is used to remember the icons 
position on the desktop, among other things, and contains the list of files
and directories present in the remote directory.

Note that deleted files may still be present in this .DS_Store file.");
 script_set_attribute(attribute:"solution", value:
"- Configure your web server so as to prevent the download of .DS_Store files
- Mac OS X users should configure their workstation to disable the creation
  of .DS_Store files on network shares.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT1629");
 script_set_attribute(attribute:"see_also", value:"http://kb.adobe.com/selfservice/viewContent.do?externalId=tn_16831&sliceId=2");
 script_set_attribute(attribute:"see_also", value:"http://www.greci.cc/?p=10");

 script_set_attribute(attribute:"plugin_publication_date", value:"2001/09/14");
 script_set_attribute(attribute:"vuln_publication_date", value:"2001/09/10");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("no404.nasl", "http_version.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check for .DS_Store in the root of the website 
# Could be improved to use the output of webmirror.nasl to create a list of folders to try... 

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("byte_func.inc");

function extract_files_from_dsstore(ds)
{
  local_var	len, off, offs, i, l, name, j, names_l, c, asc;

  if ("Bud1" >!< ds) return NULL;
  set_byte_order(BYTE_ORDER_BIG_ENDIAN);
  len = strlen(ds);
  if (len < 0x58)
  {
    debug_print("Short header\n");
    return NULL;
  }

  offs[0] = getword(blob: ds, pos: 0x14);
  offs[1] = getword(blob: ds, pos: 0x16);
  off = len;
  for (i = 0; i < 2; i ++)
    if (offs[i] >= 0x58 && offs[i] < len && offs[i] < off)
      off = offs[i];
  offs = NULL;
  if (off >= len) return NULL;
  names_l = make_array();
  for (i = off; i < len; i +=2)
  {
    l = getdword(blob: ds, pos: i);
    if (l > 1 && l < 255)	# Reasonable size
    {
     name = '';
     for (j = 0; j < l; j ++)
       if (ds[i+4 + 2*j] == '\0')
       {
         c = ds[i+4 + 2*j +1];
         asc = ord(c);
         if (asc < 32 || asc > 127)
         {
           name = NULL;
	   break;
         }
         name += c;
       }
       else
       {
         name = NULL;
         break;
       }
     if (! isnull(name))
     {
       names_l[name] = 1;
       i += 4 + 2 * l;
       if (substr(ds, i, i + 7) == "cmmtustr")
       {
         i += 7;
         i += getdword(blob: ds, pos: i);
       }
     }
   }
 }
 return keys(names_l);
}

port = get_http_port(default: 80);

if (thorough_tests)
 dirs = list_uniq("/", cgi_dirs(), 
   get_kb_list(strcat("www/", port, "/content/directories")));
else
 dirs = make_list("/");

foreach dir (dirs)
{
  if (dir == "" || dir[strlen(dir)-1] != "/") dir += "/";
  u = strcat(dir, ".DS_Store");
  r = http_send_recv3(method: "GET", item: u, port:port);
  if (isnull(r)) exit(0);
  if (r[0] =~ "^HTTP/1\.[01.] +200 ")
  {
    l = extract_files_from_dsstore(ds: r[2]);

    if (! isnull(l))
    {
      report = '';
      if (max_index(l) > 0)
      {
        report = strcat('\n', build_url(port: port, qs: u), '\nreveals the following entries:\n');
        foreach k (l) report = strcat(report, ' ', k, '\n');
        security_warning(port:port, extra: report);
      }
      else
      {
        report = strcat('\nPlease check\n', build_url(port: port, qs: u));
        security_warning(port:port, extra: report);
      }
      exit(0);
    }
  }
  # .FBCIndex files have been obsolete for a long time
  if (thorough_tests)
  {
    r = http_send_recv3(method: 'GET', item: dir+".FBCIndex", port:port);
    if (isnull(r)) exit(0);
    if("Bud2" >< r[2])
    {
      report = strcat('\nPlease check :\n', build_url(port: port, qs: u));
      security_warning(port:port, extra: report);
    }
  }
}

