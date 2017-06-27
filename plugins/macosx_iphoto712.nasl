#TRUSTED 24e60bfbc892044229c8db99466309e37af345e8ece85bf9426e56a247ea900be979ad0f8a487604c8ee5550e8444d157ae914f105111ce4569a26272c243d187d0c96f9d9850675580313f711bfebe1588bbb06878fdc851c9ba32f4e2545796fd385fd211dbcf0b9caec6ec9b11100f3ea9ba979d3bed01714dcb3e848da3b7f45933db57002edce7b70e8d030f996e1ae4548664f7f19552a7ec1ab4faf7c65b756f03efc1be88d98cb224c2ca5856322176ce94418a085a690d266c1a0ee9c3b0f36a614704aa56b91a9484f7f86cf3dedeca16ac94977f1bfdca9f9ac7daf1983b94e37a5f9b54695bd47f5ded4ef10b1466782a2247538ac42962239f9e89cb192c4b46648d2404143c9913906486ca10d45bbb6c2e20d2700cb83b07b8346e3d8997215fd4a8c6b161539c14ab6f9cf0f22575cc5e22ddb3e235e8651a466fb9d3606d3cc51eace757c5970d3e63edaee32157dbf63952e673251fc9cadf61f80ac2493d11c1fc8141d252ea0b1691c5e1a231e397effa47a87555f13b109afba6da31251a9d84aa55ecd5dccbd8402782f7d0ea6b81a37e7a01b8d719d458f74f9e71ffbd77f656c697dc6ae721fb824537446709f832a46aec6fdcc5e52fa0d10bd4c994ac508d390a6d1be92d58217ddf0b3e85a1085899ee7837c2452cfade69944c823c76dc2b8c553f3784cdf0b5cea6bd4847353b20591b72a
#
# (C) Tenable Network Security, Inc.
#
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(30201);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2008-0043");
  script_bugtraq_id(27636);
  script_osvdb_id(41148);

  script_name(english:"iPhoto < 7.1.2 Format String Vulnerability");
  script_summary(english:"Checks version of iPhoto");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains an application that is affected by a
format string vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of iPhoto 7.1 older than version
7.1.2. Such versions are reportedly affected by a format string
vulnerability. If an attacker can trick a user on the affected host
into subscribing to a specially crafted photocast, these issues could
be leveraged to execute arbitrary code on the affected host subject to
the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=307398");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Feb/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://www.apple.com/support/downloads/iphoto712.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to iPhoto 7.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94);

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:iphoto");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}



include("macosx_func.inc");
include("ssh_func.inc");


uname = get_kb_item("Host/uname");
if (!uname) exit(0);

if (egrep(pattern:"Darwin.*", string:uname))
{
  cmd = GetBundleVersionCmd(file:"iPhoto.app", path:"/Applications");
  if (islocalhost())
    version = pread(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = ssh_open_connection();
    if (!ret) exit(0);

    version = ssh_cmd(cmd:cmd);
    ssh_close_connection();
  }

  if (version)
  {
    version = chomp(version);
    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    if (
      ver[0] == 7 &&
      (
        ver[1] == 0 ||
        (ver[1] == 1 && ver[2] < 2)
      )
    )
    {
        report = string(
          "\n",
          "The remote version of iPhoto is ", version, ".\n"
        );
        security_warning(port:0, extra:report);
    }
  }
}
