#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25705);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/13 15:33:30 $");

  script_cve_id(
    "CVE-2006-4175", 
    "CVE-2007-2466", 
    "CVE-2007-3224", 
    "CVE-2007-3225"
  );
  script_bugtraq_id(23117, 23743, 24467, 24468);
  script_osvdb_id(33524, 35743, 37246, 37247);

  script_name(english:"Sun Java System Directory Server Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Sun Java Directory Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote LDAP server has multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running the Sun Java System Directory Server, an
LDAP server from Sun Microsystems. 

The remote version of this service is affected by multiple
vulnerabilities.  Versions 6.0 and prior to 5.2 Patch 5 are affected
by :

  - list attributes information disclosure
  - Unauthorized Access (restricted to super users). 

Versions prior to 5.2 Patch 5 are affected by :

  - Denial of service due to the BER decoding handler
  - Memory corruption in the failed request handler.");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1000664.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1000951.1.html");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3b398d9");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0bf5dca5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sun Java System Directory Server 5.2 Patch 5 or 6.1 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("ldap_search.nasl");
  script_require_ports("Services/ldap", 389);

  exit(0);
}

port = get_kb_item("Services/ldap");
if (!port) port = 389;

ver = get_kb_item(string("LDAP/",port,"/vendorVersion"));
if (!ver)
  exit(0);


if ("Sun-Java(tm)-System-Directory/6.0" >< ver)
  security_hole(port);
else if (egrep(pattern:"Sun Java\(TM\) System Directory Server/", string:ver))
{
 major = ereg_replace(pattern:"^Sun Java\(TM\) System Directory Server/([0-9]+\.[0-9]+).*", string:ver, replace:"\1");
 major = split(major, sep:".", keep:FALSE);

 if (
  int(major[0]) < 5 ||
  (int(major[0]) == 5 && int(major[1]) < 2)
 ) security_hole(port);
 else if (int(major[0]) == 5 && int(major[1]) == 2)
 {
    if (egrep(pattern:".*_Patch_[0-9]+", string:ver))
    {
      patch = ereg_replace(pattern:".*_Patch_([0-9]+).*", string:ver, replace:"\1");
      if (int(patch) < 5) security_hole(port);
    }
    else security_hole(port);
 }
}

