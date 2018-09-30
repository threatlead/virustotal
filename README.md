# ![VirusTotal](https://s13.postimg.org/i1srrzd6f/Virus_Total-_Uplink-150x150.png) VirusTotal Module

## Usage

### VT

```python
import virustotal
vt = virustotal.VirusTotal(api_type='Public', api_key='...')
```

### File Report

```python
vt.file_report(resource='0f2c5c...ff08acfac')
```

### Domain Report

```python
vt.domain_report(domain='027.ru')
```

### IpAddress Report

```python
vt.ipaddress_report(ip='4.4.4.4')
```

### Query

```python
query = 'tag:email AND fs:2018-09-22T00:00:00+ AND fs:2018-09-22T03:00:00-'
hashes, offset = vt.file_search(query, offset=None)
```

### User Comments

```python
comments = vt.user_comments(user='threatlead', page=1)
print(comments['comments'])
```
