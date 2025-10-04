Function Analyze-EmailHeaders {
    Write-Host "--- ADVANCED FORENSIC EMAIL ANALYZER ---" -ForegroundColor Yellow
    Write-Host "Please paste the entire raw email source (headers and body) now." -ForegroundColor Cyan
    Write-Host "Type 'ENDINPUT' and press Enter to finish pasting." -ForegroundColor Cyan
    
    $rawContentLines = @()
    while (($line = Read-Host) -ne "ENDINPUT") {
        $rawContentLines += $line
    }
    
    $rawContent = $rawContentLines -join "`n"

    if (-not $rawContent -or $rawContent.Length -lt 100) {
        Write-Host "Error: Content was not pasted correctly or is too short. Exiting." -ForegroundColor Red
        return
    }

    # --- 1. SEPARATE HEADERS AND BODY ---
    $headers = ""
    $body = ""
    
    $headerEndMatch = $rawContent | Select-String -Pattern "`r?`n`r?`n" -NotMatch
    
    if ($headerEndMatch) {
        $separatorIndex = $rawContent.IndexOf($headerEndMatch.Line) + $headerEndMatch.Line.Length
        $headers = $rawContent.Substring(0, $separatorIndex).Trim()
        # FIX: Added $ to separatorIndex
        $body = $rawContent.Substring($separatorIndex).Trim()
    } else {
        $headers = $rawContent
    }
    
    # --- 2. HEADER PARSING ---
    $headerLines = $headers -split '(\r?\n)' | Where-Object { $_.Trim() -ne "" -and $_.Trim() -ne "`r" -and $_.Trim() -ne "`n" }
    
    $keyHeaders = @{}
    $allReceived = @()
    $currentHeaderName = ""

    $keysOfInterest = @("Subject", "From", "Reply-To", "Return-Path", "Authentication-Results", "Received", "Content-Type", "Content-Transfer-Encoding", "Date")
    
    foreach ($line in $headerLines) {
        $trimmedLine = $line.Trim()

        if ($line -match "^[ `t]") {
            if ($currentHeaderName) {
                if ($currentHeaderName -ceq "Received") {
                    $allReceived[-1] += " " + $trimmedLine
                } elseif ($keyHeaders.ContainsKey($currentHeaderName)) {
                    $keyHeaders[$currentHeaderName] += " " + $trimmedLine
                }
            }
            continue
        }

        if ($trimmedLine -match "^(.+?): (.+)$") {
            $name = $Matches[1].Trim()
            $value = $Matches[2].Trim()

            $matchedKey = $keysOfInterest | Where-Object { $_ -ceq $name } | Select-Object -First 1

            if ($matchedKey) {
                $currentHeaderName = $matchedKey
                if ($matchedKey -ceq "Received") {
                    $allReceived += $value 
                } else {
                    $keyHeaders[$matchedKey] = $value
                }
            } else {
                $currentHeaderName = "" 
            }
        } else {
            $currentHeaderName = "" 
        }
    }
    
    $keyHeaders["Received"] = $allReceived


    # --- 3. LINK EXTRACTION ---
    Write-Host "`n"
    Write-Host "--- EXTRACTED LINKS FOR ANALYSIS ---" -ForegroundColor Green
    $links = [regex]::Matches($rawContent, '(?i)(?:https?://|www\.)\S+').Value | Sort-Object -Unique
    
    if ($links.Count -gt 0) {
        $i = 1
        foreach ($link in $links) {
            $cleanLink = $link -replace '[>"<,)]$', ''
            Write-Host "[$i]`t$cleanLink" -ForegroundColor Yellow
            $i++
        }
    } else {
        Write-Host "No clear HTTP/HTTPS links found in the content." -ForegroundColor DarkGray
    }


    # --- 4. ATTACHMENT HASHING (ROBUST BASE64 DECODING) ---
    Write-Host "`n"
    Write-Host "--- ATTACHMENT ANALYSIS (Base64 Detection) ---" -ForegroundColor Green
    
    $rxOptions = [System.Text.RegularExpressions.RegexOptions] 

    $boundary = [regex]::Match($headers, 'boundary="([^"]+)"', $rxOptions::IgnoreCase).Groups[1].Value

    if ($boundary) {
        $parts = $rawContent -split "--$boundary"
        $j = 1

        foreach ($part in $parts) {
            $part = $part.Trim()
            if (-not $part) { continue }
            
            if ($part -match '(?i)Content-Transfer-Encoding:\s*base64' -and $part -match '(?i)Content-Disposition:\s*attachment') {
                
                $base64BlockMatch = [regex]::Match($part, "`r?`n`r?`n(.+)", $rxOptions::Singleline)
                
                if ($base64BlockMatch.Success) {
                    $base64Data = $base64BlockMatch.Groups[1].Value.Trim()
                    $base64Data = $base64Data -replace '\s', ''
                    
                    if ($base64Data.Length -gt 100) {
                        if (Get-Command Get-FileHash -ErrorAction SilentlyContinue) {
                            try {
                                $bytes = [System.Convert]::FromBase64String($base64Data)
                                $hash = (Get-FileHash -InputStream ([System.IO.MemoryStream]::new($bytes)) -Algorithm MD5).Hash
                                
                                Write-Host "Attachment Detected #$j" -ForegroundColor Cyan
                                Write-Host "`tSize (Bytes):`t$($bytes.Length)" -ForegroundColor White
                                Write-Host "`tMD5 Hash:`t`t$hash" -ForegroundColor Red
                                
                                $j++
                            } catch {
                                Write-Host "Attachment Detected #$j" -ForegroundColor Cyan
                                Write-Host "`tError: Could not decode Base64 data. Might be corrupted or invalid." -ForegroundColor Red
                                $j++
                            }
                        } else {
                            Write-Host "Attachment Detected #$j (Error: PowerShell v4.0+ required for hashing)" -ForegroundColor Red
                            $j++
                        }
                    }
                }
            }
        }
        
        if ($j -eq 1) {
            Write-Host "No Base64 encoded attachments found." -ForegroundColor DarkGray
        }

    } else {
        Write-Host "No email boundaries found. Cannot reliably check for attachments." -ForegroundColor DarkGray
    }

    # MANUAL HASHING INSTRUCTION 
    Write-Host "`n--- MANUAL ATTACHMENT HASHING INSTRUCTION ---" -ForegroundColor Green
    Write-Host "If you have saved any suspicious attachments to disk, you can manually" -ForegroundColor White
    Write-Host "generate its hash for threat intelligence lookup." -ForegroundColor White
    Write-Host "To do so, use the following command in PowerShell, replacing [filepath]:" -ForegroundColor White
    Write-Host "" -ForegroundColor White
    Write-Host "Get-FileHash -Path \"`[filepath`]`[filename`]\" -Algorithm MD5" -ForegroundColor Yellow
    Write-Host "" -ForegroundColor White

    # --- 5. TIME OF SENDING ANALYSIS ---
    Write-Host "`n"
    Write-Host "--- TIME OF SENDING ANALYSIS ---" -ForegroundColor Green
    
    $dateHeader = $keyHeaders["Date"]
    $sentTime = $null

    if ($dateHeader) {
        try {
            $dateString = $dateHeader -replace '^\w{3},\s+', '' 
            $sentTime = [DateTime]::Parse($dateString)
        } catch {
            Write-Host "Error: Could not reliably parse Date header: $dateHeader" -ForegroundColor Red
        }
    }
    
    if ($sentTime) {
        Write-Host "SENT TIMESTAMP (Local System Time):" -NoNewline -ForegroundColor White
        Write-Host "`t$($sentTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan
        
        $dayOfWeek = $sentTime.DayOfWeek
        $hour = $sentTime.Hour
        $isFlagged = $false
        $flagReason = ""
        
        if (($dayOfWeek -eq [DayOfWeek]::Saturday) -or ($dayOfWeek -eq [DayOfWeek]::Sunday)) {
            $flagReason += "WEEKEND; "
            $isFlagged = $true
        }
        
        if (($hour -lt 8) -or ($hour -ge 17)) { 
            $flagReason += "AFTER-HOURS (before 8am or after 5pm);"
            $isFlagged = $true
        }
        
        Write-Host "TIME ANALYSIS:" -NoNewline -ForegroundColor White
        
        if ($isFlagged) {
            Write-Host "`t$flagReason (RED FLAG)" -ForegroundColor Red
        } else {
            Write-Host "`tSent during standard business hours." -ForegroundColor Green
        }
    } else {
        Write-Host "SENT TIMESTAMP:" -NoNewline -ForegroundColor White
        Write-Host "`tN/A (Date header missing or unparsable)" -ForegroundColor DarkGray
    }


    # --- 6. CRITICAL HEADER OUTPUT ---
    Write-Host "`n"
    Write-Host "--- CRITICAL PHISHING ANALYSIS HEADERS ---" -ForegroundColor Yellow
    
    $from = $keyHeaders["From"]
    if (-not $from) {$from = "N/A"}
    
    $replyTo = $keyHeaders["Reply-To"]
    if (-not $replyTo) {$replyTo = "N/A"}
    
    $authResults = $keyHeaders["Authentication-Results"]
    if (-not $authResults) {$authResults = "N/A"}
    
    $returnPath = $keyHeaders["Return-Path"]
    if (-not $returnPath) {$returnPath = "N/A"}
    
    Write-Host "`n[IDENTITY & DECEPTION CHECKS]" -ForegroundColor Green
    
    Write-Host "FROM:" -NoNewline -ForegroundColor White
    Write-Host "`t`t`t$from" -ForegroundColor Gray
    
    $isInconsistent = $false
    if (($replyTo -ne "N/A") -and ($from -ne "N/A")) {
        $fromMatch = [regex]::Match($from, '@([\w.-]+)>?$')
        # FIX: Corrected truncated regex string
        $replyMatch = [regex]::Match($replyTo, '@([\w.-]+)>?$')
        
        if ($fromMatch.Success -and $replyMatch.Success) {
            $fromDomain = $fromMatch.Groups[1].Value.ToLower()
            $replyDomain = $replyMatch.Groups[1].Value.ToLower()
            
            if ($fromDomain -ne $replyDomain) {
                $isInconsistent = $true
            }
        } else {
             $isInconsistent = $true 
        }
    }
    
    Write-Host "REPLY-TO (CRITICAL):" -NoNewline -ForegroundColor White
    if ($isInconsistent) {
        Write-Host "`t$replyTo (RED FLAG: Inconsistent Domain)" -ForegroundColor Red
    } else {
        Write-Host "`t$replyTo (Domain is consistent)" -ForegroundColor Green
    }
    
    Write-Host "`n[AUTHENTICATION RESULTS (SPF/DKIM/DMARC)]" -ForegroundColor Green
    Write-Host "AUTH-RESULTS:" -NoNewline -ForegroundColor White
    if ($authResults -ne "N/A" -and ($authResults -match "fail" -or $authResults -match "softfail")) {
        Write-Host "`t$authResults (⚠️ Failure Found!)" -ForegroundColor Red
    } else {
        Write-Host "`t$authResults" -ForegroundColor Green
    }

    Write-Host "`n[ORIGIN AND PATH TRACE]" -ForegroundColor Green
    
    if ($keyHeaders["Received"].Count -gt 0) {
        $originatingServer = $keyHeaders["Received"][-1]
        Write-Host "ORIGINATING SERVER:" -NoNewline -ForegroundColor White
        Write-Host "`t$originatingServer" -ForegroundColor Cyan
    } else {
        Write-Host "ORIGINATING SERVER:" -NoNewline -ForegroundColor White
        Write-Host "`tN/A (Received headers not found)" -ForegroundColor Red
    }

    Write-Host "RETURN-PATH:" -NoNewline -ForegroundColor White
    Write-Host "`t$returnPath" -ForegroundColor Cyan
    
    Write-Host "`n--- ANALYSIS COMPLETE ---" -ForegroundColor Yellow
} 

# Execute the function
Analyze-EmailHeaders