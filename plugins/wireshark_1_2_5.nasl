#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43350);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2009-4376", "CVE-2009-4377", "CVE-2009-4378");
  script_bugtraq_id(37407);
  script_osvdb_id(61177, 61178, 61179);
  script_xref(name:"Secunia", value:"37842");

  script_name(english:"Wireshark / Ethereal 0.9.0 to 1.2.4 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis",value:
"The remote host has an application that is affected by multiple
vulnerabilities"
  );
  script_set_attribute(attribute:"description",value:
"The installed version of Wireshark or Ethereal is potentially
affected by multiple vulnerabilities :

  - The Daintree SNA file parser can overflow a buffer.
    (Bug 4294)

  - The SMB and SMB2 dissectors can crash. (Bug 4301)

  - The IPMI dissector can crash on Windows. (Bug 4319)

These vulnerabilities can result in a denial of service, or possibly
arbitrary code execution.  A remote attacker can exploit these issues
by tricking a user into opening a maliciously crafted capture file. 
Additionally, if Wireshark is running in promiscuous mode, one of
these issues can be exploited remotely (from the same network
segment)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=4294"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=4301"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=4319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/security/wnpa-sec-2009-09.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Wireshark version 1.2.5 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/12/17"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/12/17"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/12/18"
  );
 script_cvs_date("$Date: 2013/03/21 16:56:11 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("SMB/Wireshark/Installed");

exit(0);
}

include("global_settings.inc");

# Check each install.
installs = get_kb_list("SMB/Wireshark/*");
if (isnull(installs)) exit(0, "The 'SMB/Wireshark/*' KB items are missing.");

info="";
info2="";
foreach install(keys(installs))
{
  if ("/Installed" >< install) continue;

  version = install - "SMB/Wireshark/";
  ver = split(version, sep:".", keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Affects 0.9.0 to 1.2.4
  if (
    (ver[0] == 0 && ver[1] >= 9)
    ||
    (
      ver[0] == 1 &&
      (
        (ver[1] == 0 && ver[2] < 11) ||
        (ver[1] == 2 && ver[2] < 5)
      )
    )
  ) 
    info +=
      '\n  Path              : ' + installs[install] +
      '\n  Installed version : ' + version  +
      '\n  Fixed version     : 1.2.5\n';
  else
    info2 += '  - Version ' + version + ', under ' + installs[install] +'\n';
}

# Report if any were found to be vulnerable
if (info)
{
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 4) s = "s of Wireshark / Ethereal are";
    else s = " of Wireshark / Ethereal is";

    report = string(
      "\n",
      "The following vulnerable instance", s, " installed :\n",
      "\n",
      info
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
if (info2)
  exit(0, "The following instance(s) of Wireshark / Ethereal are installed and are not vulnerable : "+info2);
