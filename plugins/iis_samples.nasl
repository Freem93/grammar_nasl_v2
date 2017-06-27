#
# (C) Tenable Network Security, Inc.
#

# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# updated for Westpoint ltd. by Paul Johnston <paul@westpoint.ltd.uk>
#
# Script audit and contributions from Carmichael Security 
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Bugtraq message archive

# commented out 8/30/09, article not available. mail sent to SF 

# Reference : 
# http://online.securityfocus.com/infocus/1318


include("compat.inc");

if(description)
{
 script_id(10370);
 script_version ("$Revision: 1.39 $");
 script_osvdb_id(283);
 script_cvs_date("$Date: 2014/06/09 20:25:40 $");


 script_name(english:"Microsoft IIS Dangerous Sample Files Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting sample files." );
 script_set_attribute(attribute:"description", value:
"Some of the IIS sample files are present.

They all contain various security flaws which could allow 
an attacker to execute arbitrary commands, read arbitrary files 
or gain valuable information about the remote system." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/infocus/1318" );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/library/cc750570.aspx" );
 script_set_attribute(attribute:"solution", value:
"Delete the whole /iissamples directory" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/04/15");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
 script_end_attributes();

 script_summary(english:"Determines whether IIS samples files are installed");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2014 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/ASP");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

#--
# List of files and text strings to scan for
#--
files[0]    = "/iissamples/issamples/fastq.idq";
messages[0] = "The template file can not be found in the location specified";
 
files[1]    = "/iissamples/issamples/query.idq";
messages[1] = messages[0];
  
files[2]    = "/iissamples/exair/search/search.idq";
messages[2] = messages[0];
 
files[3]    = "/iissamples/exair/search/query.idq";
messages[3] = messages[0];
 
files[4]    = "/iissamples/issamples/oop/qsumrhit.htw?CiWebHitsFile=/iissamples/issamples/oop/qsumrhit.htw&CiRestriction=none&CiHiliteType=Full";
messages[4] = "This is the formatting page for webhits summary highlighting.";
    
files[5]    = "/iissamples/issamples/oop/qfullhit.htw?CiWebHitsFile=/iissamples/issamples/oop/qfullhit.htw&CiRestriction=none&CiHiliteType=Full";
messages[5] = "This is the formatting page for webhits full highlighting";

files[6]    = "/scripts/samples/search/author.idq";
messages[6] = messages[0];

files[7]    = "/scripts/samples/search/filesize.idq";
messages[7] = messages[0];
    
files[8]    = "/scripts/samples/search/filetime.idq";
messages[8] = messages[0];
 
files[9]    = "/scripts/samples/search/queryhit.idq";
messages[9] = messages[0];
 
files[10]    = "/scripts/samples/search/simple.idq";
messages[10] = messages[0];
 
files[11]    = "/iissamples/exair/howitworks/codebrws.asp";
messages[11] = "ASP Source code browser";
    
files[12]    = "/iissamples/issamples/query.asp";
messages[12] = "Sample ASP Search Form";

# these produce false positive against IIS

# files[0]    = "/scripts/samples/search/qfullhit.htw",
# messages[0] = "The format of QUERY_STRING is invalid.");
# files[0]    = "/scripts/samples/search/qsumrhit.htw",
# messages[0] = "The format of QUERY_STRING is invalid.");
        
#--
# Scan for all the files in the list
#--
found_files = "";


port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);


for(i = 0; files[i]; i = i + 1)
{
  res = http_send_recv3(method:"GET", item:files[i], port:port);
  if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

  if (messages[i] >< res[2])
  {
    found_files = string(found_files, files[i], "\n");
  }
}

#--
# Report any holes found
#--
if(found_files != "")
{
  msg = string("\nThe following files are present :\n\n");
  report = string(msg, found_files);  
  security_note(port:port, extra:report);
}
