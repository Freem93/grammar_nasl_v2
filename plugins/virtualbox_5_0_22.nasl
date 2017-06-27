#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92458);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/10/25 16:58:36 $");

  script_cve_id(
    "CVE-2016-2105",
    "CVE-2016-2106",
    "CVE-2016-2107",
    "CVE-2016-2109",
    "CVE-2016-2176",
    "CVE-2016-3612"
  );
  script_bugtraq_id(
    87940,
    89744,
    89746,
    89757,
    89760
  );
  script_osvdb_id(
    137577,
    137896,
    137897,
    137898,
    137899
  );
  script_xref(name:"EDB-ID", value:"39768");

  script_name(english:"Oracle VM VirtualBox < 5.0.22 Multiple Vulnerabilities (July 2016 CPU)");
  script_summary(english:"Performs a version check on VirtualBox.exe.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Oracle VM VirtualBox application installed on the remote host is a
version prior to 5.0.22. It is, therefore, affected by multiple
vulnerabilities in the bundled OpenSSL component :

  - A heap buffer overflow condition exists in the
    EVP_EncodeUpdate() function within file
    crypto/evp/encode.c that is triggered when handling
    a large amount of input data. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition. (CVE-2016-2105)

  - A heap buffer overflow condition exists in the
    EVP_EncryptUpdate() function within file
    crypto/evp/evp_enc.c that is triggered when handling a
    large amount of input data after a previous call occurs
    to the same function with a partial block. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (CVE-2016-2106)

  - Flaws exist in the aesni_cbc_hmac_sha1_cipher()
    function in file crypto/evp/e_aes_cbc_hmac_sha1.c and
    the aesni_cbc_hmac_sha256_cipher() function in file
    crypto/evp/e_aes_cbc_hmac_sha256.c that are triggered
    when the connection uses an AES-CBC cipher and AES-NI
    is supported by the server. A man-in-the-middle attacker
    can exploit these to conduct a padding oracle attack,
    resulting in the ability to decrypt the network traffic.
    (CVE-2016-2107)

  - Multiple unspecified flaws exist in the d2i BIO
    functions when reading ASN.1 data from a BIO due to
    invalid encoding causing a large allocation of memory.
    An unauthenticated, remote attacker can exploit these to
    cause a denial of service condition through resource
    exhaustion. (CVE-2016-2109)

  - An out-of-bounds read error exists in the
    X509_NAME_oneline() function within file
    crypto/x509/x509_obj.c when handling very long ASN1
    strings. An unauthenticated, remote attacker can exploit
    this to disclose the contents of stack memory.
    (CVE-2016-2176)");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?453b5f8c");
  script_set_attribute(attribute:"see_also", value:"https://www.virtualbox.org/wiki/Changelog");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle VM VirtualBox version 5.0.22 or later as referenced
in the July 2016 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("virtualbox_installed.nasl", "macosx_virtualbox_installed.nbin");
  script_require_ports("installed_sw/Oracle VM VirtualBox", "installed_sw/VirtualBox");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app  = NULL;
apps = make_list('Oracle VM VirtualBox', 'VirtualBox');

foreach app (apps)
{
  if (get_install_count(app_name:app)) break;
  else app = NULL;
}

if (isnull(app)) audit(AUDIT_NOT_INST, 'Oracle VM VirtualBox');

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

ver  = install['version'];
path = install['path'];

# Affected :
# 5.0.x < 5.0.22
if  (ver =~ '^5\\.0' && ver_compare(ver:ver, fix:'5.0.22', strict:FALSE) < 0) fix = '5.0.22';
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);

port = 0;
if (app == 'Oracle VM VirtualBox')
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;
}

report =
  '\n  Path              : ' + path +
  '\n  Installed version : ' + ver +
  '\n  Fixed version     : ' + fix +
  '\n';
security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
exit(0);
