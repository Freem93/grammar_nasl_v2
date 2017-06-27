#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80885);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/24 13:12:22 $");

  script_cve_id(
    "CVE-2014-3513",
    "CVE-2014-3566",
    "CVE-2014-3567",
    "CVE-2014-3568"
  );
  script_bugtraq_id(70574, 70584, 70585, 70586);
  script_osvdb_id(113251, 113373, 113374, 113377);
  script_xref(name:"CERT", value:"577193");

  script_name(english:"IBM General Parallel File System Multiple Vulnerabilities (Windows) (POODLE)");
  script_summary(english:"Checks the local version of GPFS.");

  script_set_attribute(attribute:"synopsis", value:
"A clustered file system on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"A version of IBM General Parallel File System (GPFS) 3.5.x prior to
3.5.0.21 is installed on the remote Windows host. It is, therefore,
affected by the following OpenSSL related vulnerabilities :

  - An error exists related to DTLS SRTP extension handling
    and specially crafted handshake messages that can allow
    denial of service attacks via memory leaks.
    (CVE-2014-3513)

  - An error exists related to the way SSL 3.0 handles
    padding bytes when decrypting messages encrypted using
    block ciphers in cipher block chaining (CBC) mode.
    Man-in-the-middle attackers can decrypt a selected byte
    of a cipher text in as few as 256 tries if they are able
    to force a victim application to repeatedly send the
    same data over newly created SSL 3.0 connections. This
    is also known as the 'POODLE' issue. (CVE-2014-3566)

  - An error exists related to session ticket handling that
    can allow denial of service attacks via memory leaks.
    (CVE-2014-3567)

  - An error exists related to the build configuration
    process and the 'no-ssl3' build option that allows
    servers and clients to process insecure SSL 3.0
    handshake messages. (CVE-2014-3568)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=isg3T1021546");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=isg3T1021548");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value: "https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20141015.txt");
  script_set_attribute(attribute:"see_also", value: "https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"Upgrade to GPFS 3.5.0.21 or later.

If GPFS multiclustering is configured on Windows nodes, consult the
vendor advisory for detailed instructions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:general_parallel_file_system");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("ibm_gpfs_installed.nbin");
  script_require_keys("installed_sw/IBM General Parallel File System");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "IBM General Parallel File System";
install  = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version  = install['version'];
path     = install['path'];

if (version !~ "^3\.5\.") audit(AUDIT_NOT_INST, app_name + " 3.5.x");
if (version =~ "^3(\.5(\.0)?)?$") audit(AUDIT_VER_NOT_GRANULAR, app_name, version);

fix = "3.5.0.21";

# Affected :
# 3.5.x < 3.5.0.21
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_warning(extra:report, port:port);
  }
  else security_warning(port:port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
