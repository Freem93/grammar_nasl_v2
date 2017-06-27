#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41029);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2009-2562", "CVE-2009-2563");
  script_bugtraq_id(35748);
  script_osvdb_id(56017, 56018);

  script_name(english:"Wireshark / Ethereal 0.9.2 to 1.0.9 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute( attribute:"synopsis", value:
"The remote host has an application that is affected by multiple
vulnerabilities."  );
  script_set_attribute( attribute:"description", value:
"The installed version of Wireshark or Ethereal is affected by
multiple issues :

  - The AFS dissector could crash. (Bug 3564)

  - The infiniband dissector could crash on some platforms.
    (CVE-2009-2563)

  - The OpcUa dissector could use excessive CPU and memory.
    (Bug 3986)

These vulnerabilities could result in a denial of service. A remote
attacker could exploit these issues by tricking a user into opening a
maliciously crafted capture file. Additionally, if Wireshark is
running in promiscuous mode, one of these issues could be exploited
remotely (from the same network segment)."  );

  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/security/wnpa-sec-2009-05.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3564"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3986"
  );

  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Wireshark 1.0.9 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/09/15"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/09/21"
  );

 script_cvs_date("$Date: 2016/05/06 17:22:03 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_dependencies("wireshark_installed.nasl");
  script_require_keys("SMB/Wireshark/Installed");

  exit(0);
}

include("global_settings.inc");

#Check each install
installs = get_kb_list("SMB/Wireshark/*");
if (isnull(installs)) exit(0, "Unable to detect any Wireshark installs.");

info = "";
info2 = "";
foreach install(keys(installs))
{
  if ("/Installed" >< install) continue;

  version = install - "SMB/Wireshark/";
  ver = split(version, sep:".", keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  #Affects 0.9.2 to 1.0.8
  if (
    (
      ver[0] == 0 &&
      (
        (ver[1] == 9 && ver[2] >= 2) ||
         ver[1] > 9
       )
    ) ||
    (ver[0] == 1 && ver[1] == 0 && ver[2] < 9)
  ) 
    info +=
      '\n  Path              : ' + installs[install] +
      '\n  Installed version : ' + version  +
      '\n  Fixed version     : 1.0.9\n';
  else
    info2 += '  - Version ' + version + ', under ' + installs[install] +'\n';
}

#Report if any were found to be vulnerable
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
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(get_kb_item("SMB/transport"));
}
if (info2)
  exit(0, "The following instance(s) of Wireshark / Ethereal are installed and are not vulnerable : "+info2);
