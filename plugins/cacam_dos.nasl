#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(20840);
 script_version("$Revision: 1.18 $");
 script_cve_id("CVE-2006-0529", "CVE-2006-0530");
 script_bugtraq_id(16475);
 script_osvdb_id(21146, 21147);

 script_name(english:"CA Multiple Products Message Queuing Multiple Remote DoS");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote messaging service." );
 script_set_attribute(attribute:"description", value:
"The remote version of CA Message Queuing Service is vulnerable 
to two flaws that could lead to a denial of service :

  - Improper handling of specially crafted TCP packets on 
    port 4105 (CVE-2006-0529)

  - Failure to handle spoofed UDP CAM requests 
    (CVE-2006-0530)"
 );
  # http://supportconnectw.ca.com/public/ca_common_docs/camsecurity_notice.asp
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6647fd25" );
 script_set_attribute(attribute:"solution", value:
"CA has released a set of patches for CAM 1.05, 1.07 and 1.11." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/02/02");
 script_cvs_date("$Date: 2016/05/04 14:30:40 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:ca:messaging");
script_end_attributes();


 script_summary(english:"Determines if the remote CAM service is vulnerable to a DoS");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
 script_family(english:"Denial of Service");
 script_dependencies("cacam_detect.nasl");
 script_require_keys("CA/MessageQueuing");
 script_require_ports(4105);
 exit(0);
}

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
# 1.05
# < 1.07 build 220_16
# 1.07 build 230 & 231
# < 1.11 build 29_20

if ( (main < 1) ||
     ((main == 1) && (revision < 7)) ||
     ((main == 1) && (revision > 7) && (revision < 11)) )
{
 security_warning(port);
}
else if (main == 1)
{
 if (revision == 7)
 {
  if ( (build < 220) ||
       ( (build == 220) && (build_rev < 16) ) )
    security_warning(port);
  else if ((build == 230) || (build == 231))
    security_warning(port);
 }
 else if (revision == 11)
 {
  if ( (build < 29) ||
       ( (build == 29) && (build_rev < 20) ) )
    security_warning(port);
 }
}
