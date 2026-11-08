# Adoptium Temurin -- the recommended modern OpenJDK distribution. Pairs with
# app-jre-uninstall: that script removes legacy Oracle JRE 6/7/8, this script
# installs the current LTS JDK so applications that genuinely need a JRE get a
# supported one. The Adoptium API exposes a stable "latest GA installer" URL.
#
# Params:
#   $Params.Version -- "21" (default), "17", "11" -- LTS feature version

$ver = $Params.Version
if (-not $ver) { $ver = "21" }
$url = "https://api.adoptium.net/v3/installer/latest/$ver/ga/windows/x64/jdk/hotspot/normal/eclipse"
# Adoptium's MSI is a Wix bundle. Default flags install to %ProgramFiles%\Eclipse Adoptium\
# without modifying PATH or registering as the system JDK -- we leave those calls to
# whoever provisioned the host. /qn /norestart already covered by Install-FromUrl.
$exit = Install-FromUrl -Url $url -ProductName "Eclipse Temurin JDK $ver" -Kind "msi"
Write-Output "[falcon-extras] temurin-install version=$ver exit=$exit host=$env:COMPUTERNAME"
exit $exit
