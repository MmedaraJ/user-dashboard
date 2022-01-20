$(document).ready(function(){
    $('.remove').click(function(event){
        $('#deleteModal').modal('toggle', $(this));
    })
    $('#deleteModal').on('show.bs.modal', function (event) {
        var button = $(event.relatedTarget)
        var recipient = button.data('whatever')
        $(this).find('.modal-title').text('Delete user #' + recipient)
        $(this).find('.modal-body').text('Are you sure you want to delete user #' + recipient + '?')

        $('.yes').click(function(){
            url = "/remove/" + recipient
            $('.yes').attr("href", url)
        })
    })
    $('.close, .no').click(function(){
        $('#deleteModal').modal('hide')
    })
})