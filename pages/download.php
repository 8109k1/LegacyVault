<?php
require_once __DIR__ . '/../includes/bootstrap.php'; require_document_otp();
$id=(int)($_GET['id']??0);$stmt=db()->prepare('SELECT original_name,stored_name,mime_type,file_size FROM documents WHERE id=? AND user_id=?');$stmt->execute([$id,(int)$_SESSION['user_id']]);$d=$stmt->fetch();
if(!$d){http_response_code(404);exit('Document not found.');}
$path=__DIR__.'/../storage/uploads/'.$d['stored_name'];if(!is_file($path)){http_response_code(404);exit('File is missing from storage.');}
header('X-Content-Type-Options: nosniff');header('Content-Type: '.$d['mime_type']);header('Content-Length: '.filesize($path));header('Content-Disposition: attachment; filename="'.str_replace(['"','\\',"\r","\n"],'_',basename($d['original_name'])).'"');readfile($path);exit;
