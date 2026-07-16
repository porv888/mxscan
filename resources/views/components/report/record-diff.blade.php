@props(['remove' => [], 'add' => []])

@if($remove !== [] || $add !== [])
<section class="report-record-diff" aria-label="DMARC record changes">
    <h5>Before and after</h5>
    @foreach($remove as $value)
        <div class="report-record-diff-row report-record-diff-row--remove">
            <strong>Remove</strong><code>{{ $value }}</code>
        </div>
    @endforeach
    @foreach($add as $value)
        <div class="report-record-diff-row report-record-diff-row--add">
            <strong>Add</strong><code>{{ $value }}</code>
        </div>
    @endforeach
</section>
@endif
