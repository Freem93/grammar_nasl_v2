#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3207) exit(0);

include("compat.inc");

if (description)
{
  script_id(38206);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2009-1119");
  script_bugtraq_id(34449);
  script_osvdb_id(53591, 53592);
  script_xref(name:"Secunia", value:"34699");

  script_name(english:"EMC RepliStor < 6.2 SP5/6.3 SP2 Multiple Heap Overflows");
  script_summary(english:"Checks version of EMC RepliStor");

 script_set_attribute(attribute:"synopsis", value:
"The remote software is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its version, the installation of EMC RepliStor Server on 
the remote host is earlier than version 6.2 SP5 or 6.3 SP2. Such 
versions are affected by multiple heap overflow vulnerabilities. By 
sending specially crafted requests to either 'ctrlservice.exe' or 
'rep_srv.exe', an unauthorized attacker could execute arbitrary code 
on the remote system with SYSTEM level privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.fortiguardcenter.com/advisory/FGA-2009-13.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c89e2a9");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b7a129da");
 script_set_attribute(attribute:"solution", value:
"Upgrade to RepliStor 6.2 SP5 / 6.3 SP2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/29");
 script_cvs_date("$Date: 2011/03/21 14:33:47 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");

  script_dependencies("emc_replistor.nbin");
  script_require_keys("EMC/RepliStor/Version");
  script_require_ports(7144);

  exit(0);
}

version = get_kb_item("EMC/RepliStor/Version");

# Note: versions 6.2 SP5, 6.3 SP2 no longer report
# versions anonymously. So if we dont see a 
# version the remote version is probably patched.

if (!version) exit(0);

port = 7144;

if(ereg(pattern:"^Version ([0-5]\.*|(6\.[0-1]|6\.2 SP[0-4]|6\.3 SP[0-1])($|[^0-9]))",string:version) ||  # Version in KB for old versions of emc_replistor
   ereg(pattern:"^([0-5]\.*|(6\.[0-1]|6\.2\.[0-4]|6\.3\.[0-1])($|[^0-9]))",string:version)
  )
  security_hole(port);
