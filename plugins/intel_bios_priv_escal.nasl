#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(34099);
 script_version ("$Revision: 1.17 $");

 script_cve_id("CVE-2008-7096");
 script_bugtraq_id(30823);
 script_osvdb_id(49901);

 script_name(english: "Intel System Management Mode Local Privilege Escalation (INTEL-SA-00017)");
 script_summary(english: "Check Intel BIOS version");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote host is vulnerable to a local privilege escalation attack."
 );
 script_set_attribute(attribute:"description", value:
"The version of the Intel BIOS on the remote host is known to be
vulnerable to an as-yet unspecified privilege escalation attack.  It
would allow a local user with administrative privileges to upgrade
administrative privileges to System Management Mode." );
 # http://web.archive.org/web/20080903053606/http://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00017&languageid=en-fr
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?6371ebe4"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade the system BIOS on the remote host."
 );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(264);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/09/08");
 script_cvs_date("$Date: 2016/05/16 14:02:51 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english: "Misc.");
 
 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

 script_dependencies("bios_get_info_ssh.nasl", "bios_get_info_smb_reg.nasl");
 script_require_keys("BIOS/Version", "BIOS/Vendor", "BIOS/ReleaseDate");
 exit(0);
}

vendor = get_kb_item("BIOS/Vendor");
if (vendor !~ "^Intel ") exit(0);

version = get_kb_item("BIOS/Version");
if (! version) exit(0);

updates = make_list(
"JOQ3510J.86A.0942.2008.0807.1958",
"DPP3510J.86A.0484.2008.0805.2031",
"TW96510J.86A.1157.2008.0730.1429",
"PE94510M.86A.0065.2008.0801.1803",
"BTX3810J.86A.1814.2008.0807.2334" );

v = split(version, sep: '.', keep: 0);
if (max_index(v) < 6) exit(0);

foreach u (updates)
{
 w = split(u, sep: '.', keep: 0);
 if (v[0] == w[0])
 {
   if (int(v[3]) < int(w[3]) || 
       v[3] == w[3] && ( int(v[4]) < int(w[4]) ||
       	    v[4] == w[4] && int(v[5]) < int(w[5])))
    {
      security_warning(port: 0, extra: strcat('\nUpdate to ', u, '\n'));
      exit(0);
    }  
 }
}

