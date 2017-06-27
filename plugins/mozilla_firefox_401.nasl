#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53595);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/20 14:12:06 $");

  script_cve_id(
    "CVE-2011-0068",
    "CVE-2011-0069",
    "CVE-2011-0070",
    "CVE-2011-0079",
    "CVE-2011-0081",
    "CVE-2011-1202"
  );
  script_bugtraq_id(
    47641,
    47646,
    47648,
    47651,
    47653,
    47654,
    47655,
    47656,
    47657,
    47659,
    47661,
    47662,
    47663,
    47667,
    47668
  );
  script_osvdb_id(72074, 72075, 72076, 72077, 72094, 73801);
  script_xref(name:"Secunia", value:"44406");

  script_name(english:"Firefox 4.0 < 4.0.1 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Firefox 4.0 is earlier than 4.0.1.  As such,
it is potentially affected by the following security issues :

  - A buffer overflow exists in the WebGLES library.
    Additionally, the Windows version was not compiled
    with ASLR enabled. (CVE-2011-0068)

  - Multiple memory safety issues can lead to application
    crashes and possibly remote code execution.
    (CVE-2011-0069, CVE-2011-0070, CVE-2011-0079,
    CVE-2011-0081)

  - An information disclosure vulnerability exists in the
    'xsltGenerateIdFunction' function in the included
    libxslt library. (CVE-2011-1202)");

  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-12.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-17.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-18.html");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?12d3777c");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 4.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Firefox "nsTreeRange" Dangling Pointer Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'4.0.1', min:'4.0', severity:SECURITY_HOLE);
