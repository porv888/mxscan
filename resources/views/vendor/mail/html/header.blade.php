@props(['url'])
<tr>
<td class="header">
<a href="{{ $url }}" style="display: inline-block; text-decoration: none; color: #3d4852; font-size: 19px; font-weight: bold;">
{{ $slot }}
</a>
</td>
</tr>
