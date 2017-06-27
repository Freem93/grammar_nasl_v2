#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39809);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2009-3859");
  script_bugtraq_id(35624);
  script_xref(name:"EDB-ID", value:"9114");
  script_xref(name:"OSVDB", value:"55744");
  script_xref(name:"Secunia", value:"35786");

  script_name(english:"eEye Retina Wireless Scanner .rws Handling Buffer Overflow");
  script_summary(english:"Checks the local version of Retina");

  script_set_attribute( attribute:"synopsis", value:
"The network scanner installed on the remote Windows host has a buffer
overflow vulnerability."  );
  script_set_attribute( attribute:"description", value:
"The version of Retina Wireless Scanner installed on the remote host
has a local buffer overflow vulnerability.  A remote attacker could
exploit this issue by tricking a user into opening a malformed .rws
file.  This could cause the program to crash or possibly result in
the execution of arbitrary code.

Note that while Retina Wireless Scanner comes included with Retina
Network Security Scanner, it can also be installed as a standalone
application."  );
  
  script_set_attribute(
    attribute:"see_also",
    value:"http://research.eeye.com/html/advisories/published/AD20090710.html"
  );
  script_set_attribute( attribute:"solution",  value:
"Either upgrade to Retina Network Security Scanner 5.10.15 or later or
Retina WiFi Scanner (standalone) 1.0.9 or later."  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(119);
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/07/16"
  );
 script_cvs_date("$Date: 2016/05/19 17:53:37 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("retina_installed.nasl", "retina_wifi_installed.nasl");
  script_require_ports("SMB/Retina/Version", "SMB/RetinaWiFi/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");


installs = make_array();

# First, check to see if Retina Network Security Scanner is installed and
# vulnerable
ver = get_kb_item("SMB/Retina/Version");

if (ver)
{
  ver_fields = split(ver, sep:'.', keep:FALSE);
  major = int(ver_fields[0]);
  minor = int(ver_fields[1]);
  rev = int(ver_fields[2]);

  # Versions < 5.10.15 are affected
  if (
    major < 5 ||
    (major == 5 && minor < 10) ||
    (major == 5 && minor == 10 && rev < 15)
  )
  {
    path = get_kb_item("SMB/Retina/" + ver);
    installs[ver] = path;
  }
}

# Next, check to see if Retina WiFi Scanner (standalone) is installed and
# vulnerable
ver = get_kb_item("SMB/RetinaWiFi/Version");
  
if (ver)
{
  ver_fields = split(ver, sep:'.', keep:FALSE);
  major = int(ver_fields[0]);
  minor = int(ver_fields[1]);
  rev = int(ver_fields[2]);

  # Versions < 1.0.9 are affected
  if (
    major < 1 ||
    (major == 1 && minor == 0 && rev < 9)
  )
  {
    path = get_kb_item("SMB/RetinaWiFi/" + ver);
    installs[ver] = path;
  }
}

if (max_index(keys(installs)))
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Nessus detected the following vulnerable installation(s) :\n"
    );

    foreach ver (keys(installs))
    {
      report += string(
        "\n",
        "  Path    : ", installs[ver], "\n",
        "  Version : ", ver, "\n"
      );
    }
    
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
