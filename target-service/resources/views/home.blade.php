@extends('layouts.app')

@section('content')
<div class="container">
    <div class="row justify-content-center">
        <div class="col-md-8">
            <div class="card">
                <div class="card-header">{{ __('Dashboard') }}</div>

                <div class="card-body">
                    @if (session('status'))
                        <div class="alert alert-success" role="alert">
                            {{ session('status') }}
                        </div>
                    @endif
                    @guest
                        {{__('Hello Guest')}}
                    @else
                        {{ __('You are logged in!') }}
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
                            {{$users ?? '' }}
                    @endguest
<<<<<<< HEAD

=======
                    @endguest
>>>>>>> Add target-service
=======
                    {{$users ?? '' }}
>>>>>>> WIP: tracking User
=======
                            {{$users ?? '' }}
                    @endguest

>>>>>>> Logging UserID
=======
                            {{$users ?? '' }}
                    @endguest

>>>>>>> 1ba10e1cba7b340282a7448f129c895f9d8e6a67
                </div>
            </div>
        </div>
    </div>
</div>
@endsection
