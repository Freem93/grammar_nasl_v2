#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14314);
 script_version("$Revision: 1.17 $");

 script_cve_id("CVE-2004-1701", "CVE-2004-1702");
 script_bugtraq_id(10899, 10900);
 script_osvdb_id(8406, 14664);

 script_name(english:"Cfengine AuthenticationDialogue() Function Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial of service vulnerability.
Cfengine is running on this remote host.");

 script_set_attribute(attribute:"description", value:
"Cfengine cfservd is reported prone to a remote heap-based buffer
overrun vulnerability. 

The vulnerability presents itself in the cfengine cfservd
AuthenticationDialogue() function.  The issue exists due to a lack of
sufficient boundary checks performed on challenge data that is
received from a client. 

In addition, cfengine cfservd is reported prone to a remote denial of
service vulnerability.  The vulnerability presents itself in the
cfengine cfservd AuthenticationDialogue() function which is
responsible for processing SAUTH commands and also performing RSA
based authentication.  The vulnerability presents itself because
return values for several statements within the
AuthenticationDialogue() function are not checked." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2004/Aug/401" );
 script_set_attribute(attribute:"see_also", value:"http://security.gentoo.org/glsa/glsa-200408-08.xml" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to 2.1.8 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/20");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/08/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/09");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 
 script_summary(english:"check for cfengine flaw based on its version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_require_ports(5308);

 script_dependencies("cfengine_detect.nasl");
 exit(0);
}

port = 5308;
if ( ! get_kb_item("cfengine/running") ) exit(0);
version = get_kb_item("cfengine/version");
if (version)
{
 if (egrep(pattern:"^2\.(0\.|1\.[0-7]([^0-9]|$))", string:version))
  security_warning(port);
}
