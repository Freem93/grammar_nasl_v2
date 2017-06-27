#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55927);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/06/03 20:36:41 $");

  script_bugtraq_id(48385);
  script_osvdb_id(73233);
  script_xref(name:"IAVB", value:"2011-B-0084");

  script_name(english:"Citrix EdgeSight Load Tester Buffer Overflow");
  script_summary(english:"Checks Citrix EdgeSight version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"It is possible to execute code on the remote server using a stack
overflow vulnerability in Citrix EdgeSight Load Tester."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A stack overflow vulnerability exists in the Citrix EdgeSight Load
Tester software installed on the remote host. 

By sending a specially crafted message to the server, a remote
attacker can leverage this vulnerability to execute arbitrary code on
the server as the SYSTEM account. 

Versions prior to 3.8.1 are affected."
  );
  script_set_attribute(
    attribute:"solution",
    value:"Citrix has released version 3.8.1, which resolves the issue."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/22");
  script_set_attribute(attribute:"see_also", value:"http://www.citrix.com");
  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX129699");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-226/");

  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_dependencies('citrix_eslt_detect.nbin');
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
  script_require_keys('Services/CitrixESLT');

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

# Figure out which port(s) to use
port = get_service(svc:'CitrixESLT', default:18747, exit_on_fail:TRUE);

# Get the version
version = get_kb_item_or_exit("Citrix/ESLT/"+port+"/Version");

if (ver_compare(ver:version, fix:"3.8.1", strict:FALSE) == -1)
    security_hole(port:port);
