#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58006);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/09/17 11:05:43 $");

  script_cve_id("CVE-2011-3026");
  script_bugtraq_id(52049);
  script_osvdb_id(79294);

  script_name(english:"Firefox 3.6.x < 3.6.27 'png_decompress_chunk' Integer Overflow");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a web browser that is potentially
affected by an integer overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Firefox 3.6.x is earlier than 3.6.27 and is,
therefore, potentially affected by an integer overflow vulnerability.

An integer overflow error exists in 'libpng', a library used by this
application. When decompressing certain PNG image files, this error
can allow a heap-based buffer overflow which can crash the
application or potentially allow code execution.");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-11.html");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6846f277");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 3.6.27 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'3.6.27', min:'3.6', severity:SECURITY_HOLE);