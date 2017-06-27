#
# (C) Tenable Network Security, Inc.
#

# vendor advisory:
# Affected Platforms:
# Windows and NetWare


include("compat.inc");

if(description)
{
 script_id(25766);
 script_version("$Revision: 1.14 $");

 script_cve_id("CVE-2007-0060");
 script_bugtraq_id(25051);
 script_osvdb_id(38598);

 script_name(english:"CA Multiple Products Message Queuing Server (Cam.exe) Remote Overflow");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host due to a flaw in the
CAM service." );
 script_set_attribute(attribute:"description", value:
"The remote version of CA Message Queuing Service contains a 
stack overflow that may allow an attacker to execute
arbitrary code on the remote host with SYSTEM privileges. 

An attacker does not need to be authenticated to exploit this flaw." );
 script_set_attribute(attribute:"see_also", value:"http://www.ca.com/us/securityadvisor/newsinfo/collateral.aspx?cid=149809" );
 script_set_attribute(attribute:"solution", value:
"CA has released a set of patches for CAM 1.11." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/07/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/07/25");
 script_cvs_date("$Date: 2016/05/04 14:30:40 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 script_summary(english:"Determines if the remote CAM service is vulnerable to a buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencies("cacam_detect.nasl", "os_fingerprint.nasl");
 script_require_keys("CA/MessageQueuing", "Host/OS");
 script_require_ports(4105);
 exit(0);
}


# Only Windows and NetWare are affected per CA's advisory.
os = get_kb_item("Host/OS");
if (!os || ("Windows" >!< os && "Novell Netware" >!< os)) exit(0);


version = get_kb_item ("CA/MessageQueuing");
if (isnull(version))
  exit (0);

port = 4105;

main = ereg_replace (pattern:"^([0-9]+)\.[0-9]+ \(Build [0-9]+_[0-9]+\)$", string:version, replace:"\1");
revision = ereg_replace (pattern:"^[0-9]+\.([0-9]+) \(Build [0-9]+_[0-9]+\)$", string:version, replace:"\1");

build = ereg_replace (pattern:"^[0-9]+\.[0-9]+ \(Build ([0-9]+)_[0-9]+\)$", string:version, replace:"\1");
build_rev = ereg_replace (pattern:"^[0-9]+\.[0-9]+ \(Build [0-9]+_([0-9]+)\)$", string:version, replace:"\1");


main = int(main);
revision = int (revision);
build = int(build);
build_rev = int (build_rev);


# vulnerable :
# < 1.10
# < 1.10 build 54_4
# < 1.11 build 54_4

if ( (main < 1) ||
     (main == 1 && revision < 10) ||
     (main == 1 && revision == 10 && build < 54) ||
     (main == 1 && revision == 10 && build == 54 && build_rev < 4) ||
     (main == 1 && revision == 11 && build < 54) ||
     (main == 1 && revision == 11 && build == 54 && build_rev < 4) )
{
 security_hole(port);
}

