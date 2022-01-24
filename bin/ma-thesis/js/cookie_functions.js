function getCookie(name) {
    var dc = document.cookie;
    var prefix = name + "=";
    var begin = dc.indexOf("; " + prefix);
    if (begin === -1) {
    begin = dc.indexOf(prefix);
    if (begin !== 0) return null;
    }
    else{
    begin += 2;
    var end = document.cookie.indexOf(";", begin);
    if (end === -1) {
        end = dc.length;
    }
    }
    return decodeURI(dc.substring(begin + prefix.length, end));
}

function setCookie(cname, cvalue, exhours) {
    const d = new Date();
    d.setTime(d.getTime() + (exhours*60*60*1000));
    let expires = "expires="+ d.toUTCString();
    document.cookie = cname + "=" + cvalue + ";" + expires + ";path=/;SameSite=None;Secure";
  }