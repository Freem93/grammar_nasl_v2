#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51511);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/12/18 14:26:56 $");

  script_cve_id(
    "CVE-2011-0470",
    "CVE-2011-0471",
    "CVE-2011-0472",
    "CVE-2011-0473",
    "CVE-2011-0474",
    "CVE-2011-0475",
    "CVE-2011-0476",
    "CVE-2011-0477",
    "CVE-2011-0478",
    "CVE-2011-0479",
    "CVE-2011-0480",
    "CVE-2011-0481",
    "CVE-2011-0482",
    "CVE-2011-0483",
    "CVE-2011-0484",
    "CVE-2011-0485"
  );
  script_bugtraq_id(45788, 47154);
  script_osvdb_id(
    70453,
    70454,
    70455,
    70456,
    70457,
    70458,
    70459,
    70460,
    70461,
    70462,
    70463,
    70464,
    70465,
    70466,
    70467,
    70468
  );
  script_xref(name:"Secunia", value:"42850");

  script_name(english:"Google Chrome < 8.0.552.237 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 8.0.552.237.  Such versions are reportedly affected by multiple
vulnerabilities :

  - A browser crash exists in extensions notification
    handling. (Issue #58053)

  - Bad pointer handling exists in node iteration.
    (Issue #65764)

  - Multiple crashes exist when printing multi-page PDFs.
    (Issue #66334)

  - A stale pointer exists with CSS + canvas. (Issue #66560)

  - A stale pointer exists with CSS + cursors.
    (Issue #66748)

  - A use-after-free error exists in PDF handling.
    (Issue #67100)

  - A stack corruption error exists after PDF out-of-memory
    conditions. (Issue #67208)

  - A bad memory access issue exists when handling
    mismatched video frame sizes. (Issue #67303)

  - A stale pointer exists with SVG use element.
    (Issue #67363)

  - An uninitialized pointer exists in the browser which is
    triggered by rogue extensions. (Issue #67393)

  - Multiple buffer overflows exist in the Vorbis decoder.
    (Issue #68115)

  - A buffer overflow exists in PDF shading. (Issue #68170)

  - A bad cast exists in anchor handling. (Issue #68178)

  - A bad cast exists in video handling. (Issue #68181)

  - A stale rendering node exists after DOM node removal.
    (Issue #68439)

  - A stale pointer exists in speech handling.
    (Issue #68666)");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b44c4173");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 8.0.552.237 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'8.0.552.237', severity:SECURITY_HOLE);
