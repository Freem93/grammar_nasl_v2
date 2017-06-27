#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3207) exit(0);


include("compat.inc");

if (description)
{
  script_id(35467);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2007-6426");
  script_bugtraq_id(27915);
  script_osvdb_id(42955);

  script_name(english:"EMC RepliStor Multiple Remote Heap Based Buffer Overflows");
  script_summary(english:"Checks version of EMC RepliStor");

 script_set_attribute(attribute:"synopsis", value:
"The remote software is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its version, the installation of EMC RepliStor Server on
the remote host is affected by multiple heap overvlow vulnerabilities. 
By sending a specially crafted request, an unauthorized attacker could
execute arbitrary code with SYSTEM level privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dade10b4" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to RepliStor 6.1 SP5 / 6.2 SP4 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/01/27");
 script_cvs_date("$Date: 2011/09/10 01:48:52 $");
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

ver = get_kb_item("EMC/RepliStor/Version");
if (!ver) exit(0);

port = 7144;

# Exit on version 6.1 SP5 / 6.2 SP4
# Version 6.1 SP2 (Build 450b)

matches = eregmatch(string:ver, pattern:"^Version ([0-9]+)\.([0-9]+) (SP([0-9])+ )?\(Build ([0-9a-z]+)\)$");
if (!isnull(matches))
{
  ver_major = int(matches[1]);
  ver_minor = int(matches[2]);
  sp    = int(matches[4]);
  build = matches[5];

  if (
      (ver_major < 6) ||
      (ver_major == 6 && ver_minor == 1 && sp < 5) ||
      (ver_major == 6 && ver_minor == 2 && sp < 4) 
     )
    security_hole(port);
}
